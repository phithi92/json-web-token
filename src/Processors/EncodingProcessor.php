<?php

namespace Phithi92\JsonWebToken\Processors;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidAuthTagException;
use Phithi92\JsonWebToken\Cryptographys\OpenSSL;
use Phithi92\JsonWebToken\Processors\Processor;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

/**
 * JweEncodingToken Class
 *
 * This class is responsible for handling the encryption and decryption
 * of JSON Web Encryption (JWE) tokens. It extends the WebToken class
 * and provides methods to create and decrypt JWE tokens using various
 * encryption algorithms, including AES, RSA, ECDH-ES, and PBES2.
 *
 * Features:
 * - Supports several key management algorithms (RSA, ECDH-ES, AES Key Wrap).
 * - Handles content encryption using AES-GCM, AES-CBC with HMAC, and more.
 * - Can process both direct encryption methods and key-wrapping techniques.
 * - **Note:** Currently, only RSA_OAEP is fully implemented and functional.
 *   Other algorithms (ECDH-ES, AES Key Wrap, PBES2, etc.) are still under development.
 *
 * Constants:
 * - Define supported encryption algorithms (e.g., AES, RSA).
 * - Error messages for invalid token structures, algorithms, or integrity checks.
 *
 * Dependencies:
 * - Requires an instance of the `CryptoManager` class for cryptographic operations.
 * - Utilizes various exceptions for error handling such as `InvalidArgumentException`.
 *
 * @status Partial (RSA_OAEP & GCM is implemented, other algorithms under development)
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EncodingProcessor extends Processor
{
    private static $type = 'JWE';

    // Direkte Schlüsselverschlüsselung
    public const ALGO_DIR = 'dir';

    // RSA Verschlüsselungsalgorithmen
    public const ALGO_RSA1_5 = 'RSA1_5';
    public const ALGO_RSA_OAEP = 'RSA-OAEP';
    public const ALGO_RSA_OAEP_256 = 'RSA-OAEP-256';

    // AES Key Wrap Algorithmen
    public const ALGO_A128KW = 'A128KW';
    public const ALGO_A192KW = 'A192KW';
    public const ALGO_A256KW = 'A256KW';

    // ECDH-ES Key Agreement Algorithmen
    public const ALGO_ECDH_ES = 'ECDH-ES';
    public const ALGO_ECDH_ES_A128KW = 'ECDH-ES+A128KW';
    public const ALGO_ECDH_ES_A192KW = 'ECDH-ES+A192KW';
    public const ALGO_ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    // ECDH-ES key using P-521
    public const ALGO_ECDH_ES_P521 = 'ECDH-ES-P521';

    public const ALGO_PBES2_HS256 = 'PBES2-HS256+A128KW';
    public const ALGO_PBES2_HS384 = 'PBES2-HS384+A192KW';
    public const ALGO_PBES2_HS512 = 'PBES2-HS512+A256KW';

    // Content Encryption Algorithms (AES-GCM)
    public const ALGO_A128GCM = 'A128GCM';
    public const ALGO_A192GCM = 'A192GCM';
    public const ALGO_A256GCM = 'A256GCM';

    // Content Encryption Algorithms
    public const SODIUM_CHACHA20_POLY1305 = 'chacha20-poly1305';

    // Inhaltsverschlüsselungsalgorithmen (AES-CBC + HMAC)
    public const ALGO_A128CBC_HS256 = 'A128CBC-HS256';
    public const ALGO_A192CBC_HS384 = 'A192CBC-HS384';
    public const ALGO_A256CBC_HS512 = 'A256CBC-HS512';

    // List of supported JWE algorithms
    public static array $supported = [
        'RSA-OAEP' => [],
        'RSA-OAEP-256' => [],
        'RSA1_5' => [],
        'A128GCM' => [],
        'A192GCM' => [],
        'A256GCM' => []
    ];

    /**
     * Constructor for initializing the cipher object.
     *
     * This method expects an instance of the Openssl class as a parameter.
     * If the provided argument is not an instance of Openssl, an InvalidArgumentException is thrown.
     *
     * @param  mixed $manager The cipher object, expected to be an instance of Openssl.
     * @throws UnsupportedAlgorithmException If the provided argument is not an instance of Openssl.
     */
    public function __construct(JwtAlgorithmManager $manager)
    {
        parent::__construct($manager);
        $this->setProvider(new OpenSSL\CryptographyProvider($manager));
    }

    public function getTokenType(): string
    {
        return self::$type;
    }

    public static function isSupported(string $algorithm): bool
    {
        return isset(self::$supported[$algorithm]);
    }

    /**
     * Hydrates a JwtTokenContainer from an encoded JWT string.
     *
     * Decodes the JWT string and initializes the appropriate data for a JWS or JWE token.
     *
     * @param  string $encodingToken The JWT string to decode and parse.
     * @return JwtTokenContainer The initialized JwtTokenContainer.
     * @throws InvalidFormatException If the token format is incorrect.
     */
    public function parse(string|array $encodingToken): JwtTokenContainer
    {
        $tokenData = explode('.', $encodingToken);

        if (count($tokenData) !== 5) {
            throw new InvalidFormatException();
        }

        $headerDecoded = Base64UrlEncoder::decode($tokenData[0], true);
        $jwtHeader = JwtHeader::fromJson($headerDecoded);
        $ivDecoded = Base64UrlEncoder::decode($tokenData[1], true);
        $encryptedKeyDecoded = Base64UrlEncoder::decode($tokenData[2], true);
        $encryptedPayloadDecoded = Base64UrlEncoder::decode($tokenData[3], true);
        $authTagDecoded = Base64UrlEncoder::decode($tokenData[4], true);

        $token = (new JwtTokenContainer())
            ->setHeader($jwtHeader)
            ->setIv($ivDecoded)
            ->setEncryptedKey($encryptedKeyDecoded)
            ->setEncryptedPayload($encryptedPayloadDecoded)
            ->setAuthTag($authTagDecoded);

        return $token;
    }


    public function verify(JwtTokenContainer $token): void
    {
        $algorithmInfo = $this->extractJweAlgorithmComponents($token->getHeader()->getAlgorithm());
        $tokenType = $algorithmInfo['key_management']['name'];

        if (
            $tokenType === self::ALGO_RSA_OAEP_256
            || $tokenType === self::ALGO_RSA_OAEP
            || $tokenType === self::ALGO_RSA1_5
        ) {
            $algo = $algorithmInfo['key_management']['hash_algorithm'];
            $valid = $this->getProvider()->verifyRsa($token->getEncryptedPayload(), $token->getAuthTag(), $algo);
        } elseif (
            $tokenType === self::ALGO_A128GCM
            || $tokenType === self::ALGO_A192GCM
            || $tokenType === self::ALGO_A256GCM
            || $tokenType === self::ALGO_DIR
        ) {
            // Diese Algorithmen benötigen keine separate Verifizierung
            $valid = true;
        } else {
            throw new UnsupportedAlgorithmException($tokenType);
        }

        if ($valid === false) {
            throw new InvalidAuthTagException();
        }
    }

    public function sign(JwtTokenContainer &$token, string $signAlgo): void
    {
        $authTag = '';
        $payload = $token->getPayload()->toJson();
        $this->getProvider()->signRsa($payload, $authTag, $signAlgo);
        $token->setAuthTag($authTag);
    }

    public function encrypt(JwtTokenContainer $token): JwtTokenContainer
    {
        $algorithmInfo = $this->extractJweAlgorithmComponents($token->getHeader()->getAlgorithm());

        if (true === isset($algorithmInfo['key_management'])) {
            $this->encryptContentKey($token, $algorithmInfo['key_management']);
        }

        $this->encryptContent($token, $algorithmInfo['content_encryption']);

        if (isset($algorithmInfo['signing_algorithm'])) {
            $signAlgo = $algorithmInfo['signing_algorithm']['hash_algorithm'];
            $this->sign($token, $signAlgo);
        }

        return $token;
    }

    public function decrypt(JwtTokenContainer $token): JwtTokenContainer
    {
        // Verarbeiten des Key Management Algorithmus
        $this->decryptContentKey($token);

        // Verarbeiten des Content Encryption Algorithmus
        $this->decryptContent($token);

        return $token;
    }

    /**
     * Generates a JWE (encrypted) token string from a JwtTokenContainer.
     *
     * @param  JwtTokenContainer $token The container holding the token's header,
     *                                  encrypted parts, and auth tag.
     * @return string The assembled JWE token string.
     */
    public function assemble(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedIv = Base64UrlEncoder::encode($token->getIv() ?? '');
        $encodedCek = Base64UrlEncoder::encode($token->getEncryptedKey() ?? $token->getCek());
        $encodedPayload = Base64UrlEncoder::encode($token->getEncryptedPayload());
        $encodedAuthTag = Base64UrlEncoder::encode($token->getAuthTag());
        return "$encodedHeader.$encodedIv.$encodedCek.$encodedPayload.$encodedAuthTag";
    }

    private function encryptContentKey(JwtTokenContainer &$token, array $algorithm): void
    {
        $bitLength = $algorithm['bit_length'];
        $cek = $this->getProvider()->randomBytes($bitLength / 8);
        $encodedCek = Base64UrlEncoder::encode($cek);
        $token->setCek($encodedCek);

        // Verarbeiten des Key Management Algorithmus
        $encryptedKey = $this->processEncryptionAlgorithm($token, $algorithm);

        $token->setEncryptedKey($encryptedKey);
    }

    /**
     * Decrypts the Content Encryption Key (CEK) from the token using the specified algorithm
     *
     * @param  JwtTokenContainer $token
     * @return void
     * @throws UnsupportedAlgorithmException
     */
    private function decryptContentKey(JwtTokenContainer &$token): void
    {
        $algorithmInfo = $this->extractJweAlgorithmComponents($token->getHeader()->getAlgorithm());
        $algorithm = $algorithmInfo['key_management'];

        $decryptedKey = $this->processDecryptionAlgorithm($token, $algorithm);

        $token->setCek($decryptedKey);
    }

    /**
     * Encrypts the content of the token based on the specified algorithm
     *
     * @param  JwtTokenContainer $token
     * @param  array             $algorithm
     * @return void
     * @throws UnsupportedAlgorithmException
     */
    private function encryptContent(JwtTokenContainer &$token, array $algorithm): void
    {
        $contentAlgorithm = $algorithm['name'];
        $contentBits = $algorithm['bit_length'] ?? 0;
        $ivLength = $algorithm['iv_length'] ?? 0;
        $macBitLength = $algorithm['mac_bit_length'] ?? 0;

        if ($ivLength > 0) {
            $iv = $this->generateIv($ivLength);
            $token->setIv($iv);
        }

        $encryptedPayload = $this->processContentEncryption($token, $contentAlgorithm, $contentBits);

        $token->setEncryptedPayload($encryptedPayload);
    }


    /**
     * Process the encryption based on the provided algorithm
     *
     * @param  JwtTokenContainer $token
     * @param  array             $algorithm
     * @return string Encrypted key
     * @throws UnsupportedAlgorithmException
     */
    private function processEncryptionAlgorithm(JwtTokenContainer $token, array $algorithm): string
    {
        if (
            $algorithm['name'] === self::ALGO_RSA_OAEP_256
            || $algorithm['name'] === self::ALGO_RSA_OAEP
            || $algorithm['name'] === self::ALGO_RSA1_5
        ) {
            return $this->getProvider()->rsaEncryptWithPublicKey($token->getCek(), OPENSSL_PKCS1_OAEP_PADDING);
        } elseif (
            $algorithm['name'] === self::ALGO_A128KW
            || $algorithm['name'] === self::ALGO_A192KW
            || $algorithm['name'] === self::ALGO_A256KW
        ) {
            return $this->getProvider()->aesKeyWrapEncrypt($token->getCek(), $algorithm['bit_length']);
        } elseif ($algorithm['name'] === self::ALGO_ECDH_ES_P521) {
            return $this->getProvider()->encryptWithECDH_ES_P521(
                $token->getRecipientPublicKey(),
                $token->getCek()
            );
        } elseif (
            $algorithm['name'] === self::ALGO_ECDH_ES
            || $algorithm['name'] === self::ALGO_ECDH_ES_A128KW
            || $algorithm['name'] === self::ALGO_ECDH_ES_A192KW
            || $algorithm['name'] === self::ALGO_ECDH_ES_A256KW
        ) {
            return $this->getProvider()->ecdhEsKeyAgreement();
        } elseif (
            $algorithm['name'] === self::ALGO_PBES2_HS256
            || $algorithm['name'] === self::ALGO_PBES2_HS384
            || $algorithm['name'] === self::ALGO_PBES2_HS512
        ) {
            return $this->getProvider()->pbes2EncryptKey(
                $token->getCek(),
                $algorithm['bit_length']
            );
        } elseif (
            $algorithm['name'] === self::ALGO_A128GCM
            || $algorithm['name'] === self::ALGO_A192GCM
            || $algorithm['name'] === self::ALGO_A256GCM
            || $algorithm['name'] === self::ALGO_DIR
        ) {
            return $token->getCek();
        } else {
            throw new UnsupportedAlgorithmException($algorithm);
        }
    }

    /**
     * Process the decryption based on the provided algorithm
     *
     * @param  JwtTokenContainer $token
     * @param  array             $algorithm
     * @return string Decrypted key
     * @throws UnsupportedAlgorithmException
     */
    private function processDecryptionAlgorithm(JwtTokenContainer $token, array $algorithm): string
    {
        if (
            $algorithm['name'] === self::ALGO_RSA_OAEP_256
            || $algorithm['name'] === self::ALGO_RSA_OAEP
            || $algorithm['name'] === self::ALGO_RSA1_5
        ) {
            return $this->getProvider()->rsaDecryptWithPrivateKey(
                $token->getEncryptedKey(),
                OPENSSL_PKCS1_OAEP_PADDING
            );
        } elseif (
            $algorithm['name'] === self::ALGO_A128KW
            || $algorithm['name'] === self::ALGO_A192KW
            || $algorithm['name'] === self::ALGO_A256KW
        ) {
            return $this->getProvider()->aesKeyWrapDecrypt($token->getEncryptedKey(), $algorithm['bit_length']);
        } elseif ($algorithm['name'] === self::ALGO_ECDH_ES_P521) {
            return $this->getProvider()->decryptWithECDH_ES_P521(
                $token->getEncryptedKey(),
                $token->getRecipientPrivateKey()
            );
        } elseif (
            $algorithm['name'] === self::ALGO_PBES2_HS256
            || $algorithm['name'] === self::ALGO_PBES2_HS384
            || $algorithm['name'] === self::ALGO_PBES2_HS512
        ) {
            return $this->getProvider()->pbes2DecryptKey(
                $token->getEncryptedKey(),
                $algorithm['bit_length']
            );
        } elseif (
            $algorithm['name'] === self::ALGO_A128GCM
            || $algorithm['name'] === self::ALGO_A192GCM
            || $algorithm['name'] === self::ALGO_A256GCM
            || $algorithm['name'] === self::ALGO_DIR
        ) {
            return $token->getEncryptedKey();
        } else {
            throw new UnsupportedAlgorithmException($algorithm['name']);
        }
    }

    /**
     * Generate a random Initialization Vector (IV)
     *
     * @param  int $ivLength
     * @return string
     */
    private function generateIv(int $ivLength): string
    {
        return $this->getProvider()->randomBytes($ivLength);
    }

    /**
     * Process encryption based on the provided content algorithm
     *
     * @param  JwtTokenContainer $token
     * @param  string            $contentAlgorithm
     * @param  int               $contentBits
     * @return string Encrypted payload
     * @throws UnsupportedAlgorithmException
     */
    private function processContentEncryption(
        JwtTokenContainer $token,
        string $contentAlgorithm,
        ?int $contentBits = null
    ): string {
        if (
            $contentAlgorithm === self::ALGO_A128KW
            || $contentAlgorithm === self::ALGO_A192KW
            || $contentAlgorithm === self::ALGO_A256KW
        ) {
            return $this->getProvider()->aesKeyWrapEncrypt(
                $token->getEncryptedKey(),
                $contentBits
            );
        } elseif (
            $contentAlgorithm === self::ALGO_A128GCM
            || $contentAlgorithm === self::ALGO_A192GCM
            || $contentAlgorithm === self::ALGO_A256GCM
        ) {
            $authTag = '';
            $encrypted = $this->getProvider()->aesGcmEncrypt(
                $token->getPayload()->toJson(),
                $contentBits,
                $token->getIv(),
                $authTag
            );
            $token->setAuthTag($authTag);
            return $encrypted;
        } elseif ($contentAlgorithm === self::ALGO_DIR) {
            return $token->getPayload()->toJson();
        } else {
            throw new UnsupportedAlgorithmException($contentAlgorithm);
        }
    }

    private function decryptContent(JwtTokenContainer &$token): void
    {
        $algorithmInfo = $this->extractJweAlgorithmComponents($token->getHeader()->getAlgorithm());
        $algorithm = $algorithmInfo['content_encryption'];
        $contentAlgorithm = $algorithm['name'];
        $bitLength = $algorithm['bit_length'] ?? null;
//        $macBitLength = $algorithmInfo['mac_bit_length'] ?? null;
        $decryptedPayload = null;

        if (
            $contentAlgorithm === self::ALGO_A128GCM
            || $contentAlgorithm === self::ALGO_A192GCM
            || $contentAlgorithm === self::ALGO_A256GCM
        ) {
            // GCM-Modus entschlüsseln
            $decryptedPayload = $this->getProvider()->aesGcmDecrypt(
                $token->getEncryptedPayload(),
                $bitLength,
                $token->getIv(),
                $token->getAuthTag()
            );
        } elseif ($contentAlgorithm === self::ALGO_DIR) {
            $decryptedPayload = $token->getEncryptedPayload();
        } else {
            throw new UnsupportedAlgorithmException($contentAlgorithm);
        }

        $token->setPayload(JwtPayload::fromJson($decryptedPayload));
    }


    private function extractJweAlgorithmComponents(string $jweAlgorithm)
    {
        $config = $this->getJweAlgorithmConfiguration();

        // Prüfen, ob der Algorithmus in der Konfiguration vorhanden ist
        if (!isset($config[$jweAlgorithm])) {
            throw new UnsupportedAlgorithmException($jweAlgorithm);
        }

        return $config[$jweAlgorithm];
    }

    private function getJweAlgorithmConfiguration(): array
    {
        return [
            // RSA Key Management Algorithmen mit Signaturalgorithmus
            self::ALGO_RSA_OAEP => [
                'algorithm_type' => 'RSA',
                'key_management' => [
                    'name' => self::ALGO_RSA_OAEP,
                    'bit_length' => 256,
                    'hash_algorithm' => 'sha256'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR
                ],
                'signing_algorithm' => [
                    'name' => 'RS256',
                    'hash_algorithm' => 'sha256',
                    'padding' => OPENSSL_PKCS1_PADDING
                ]
            ],
            self::ALGO_RSA_OAEP_256 => [
                'algorithm_type' => 'RSA',
                'key_management' => [
                    'name' => self::ALGO_RSA_OAEP_256,
                    'bit_length' => 256,
                    'hash_algorithm' => 'sha256'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR
                ],
                'signing_algorithm' => [
                    'name' => 'RS256',
                    'hash_algorithm' => 'sha256',
                    'padding' => OPENSSL_PKCS1_PADDING
                ]
            ],
            self::ALGO_RSA1_5 => [
                'algorithm_type' => 'RSA',
                'key_management' => [
                    'name' => self::ALGO_RSA1_5,
                    'bit_length' => 256,
                    'hash_algorithm' => 'sha256'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR
                ],
                'signing_algorithm' => [
                    'name' => 'RS256',
                    'hash_algorithm' => 'sha256',
                    'padding' => OPENSSL_PKCS1_PADDING
                ]
            ],

            // ECDH-ES Key Management Algorithmen mit AES Key Wrap und Signaturalgorithmus
            self::ALGO_ECDH_ES_A128KW => [
                'algorithm_type' => 'ECDSA',
                'key_management' => [
                    'name' => self::ALGO_ECDH_ES_A128KW,
                    'bit_length' => 128,
                    'hash_algorithm' => 'sha256'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'ES256',
                    'hash_algorithm' => 'sha256'
                ]
            ],
            self::ALGO_ECDH_ES_A192KW => [
                'algorithm_type' => 'ECDSA',
                'key_management' => [
                    'name' => self::ALGO_ECDH_ES_A192KW,
                    'bit_length' => 192,
                    'hash_algorithm' => 'sha384'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'ES384',
                    'hash_algorithm' => 'sha384'
                ]
            ],
            self::ALGO_ECDH_ES_A256KW => [
                'algorithm_type' => 'ECDSA',
                'key_management' => [
                    'name' => self::ALGO_ECDH_ES_A256KW,
                    'bit_length' => 256,
                    'hash_algorithm' => 'sha512'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'ES512',
                    'hash_algorithm' => 'sha512'
                ]
            ],

            // Passwortbasierte Algorithmen (PBES2) mit HMAC Signaturen
            self::ALGO_PBES2_HS256 => [
                'algorithm_type' => 'HMAC',
                'key_management' => [
                    'name' => self::ALGO_PBES2_HS256,
                    'bit_length' => 128,
                    'hash_algorithm' => 'sha256'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'HS256',
                    'hash_algorithm' => 'sha256'
                ]
            ],
            self::ALGO_PBES2_HS384 => [
                'algorithm_type' => 'HMAC',
                'key_management' => [
                    'name' => self::ALGO_PBES2_HS384,
                    'bit_length' => 192,
                    'hash_algorithm' => 'sha384'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'HS384',
                    'hash_algorithm' => 'sha384'
                ]
            ],
            self::ALGO_PBES2_HS512 => [
                'algorithm_type' => 'HMAC',
                'key_management' => [
                    'name' => self::ALGO_PBES2_HS512,
                    'bit_length' => 256,
                    'hash_algorithm' => 'sha512'
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                ],
                'signing_algorithm' => [
                    'name' => 'HS512',
                    'hash_algorithm' => 'sha512'
                ]
            ],

            // AES Key Wrap Algorithmen (ohne Key Agreement) - ohne Signatur
            self::ALGO_A128KW => [
                'algorithm_type' => 'AES',
                'key_management' => [
                    'name' => self::ALGO_A128KW,
                    'bit_length' => 128
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                    'iv_length' => 128
                ]
            ],
            self::ALGO_A192KW => [
                'algorithm_type' => 'AES',
                'key_management' => [
                    'name' => self::ALGO_A192KW,
                    'bit_length' => 192
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                    'iv_length' => 128
                ]
            ],
            self::ALGO_A256KW => [
                'algorithm_type' => 'AES',
                'key_management' => [
                    'name' => self::ALGO_A256KW,
                    'bit_length' => 256
                ],
                'content_encryption' => [
                    'name' => self::ALGO_DIR,
                    'iv_length' => 128
                ]
            ],

            // Content Encryption Algorithmen - GCM (ohne Signatur)
            self::ALGO_A128GCM => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A128GCM,
                    'bit_length' => 128,
                    'iv_length' => 96,
                    'mac_bit_length' => null
                ],
                'key_management' => [
                    'name' => self::ALGO_DIR,
                    'bit_length' => 128 // Hinzugefügt: Bit-Länge des Schlüssels
                ]
            ],
            self::ALGO_A192GCM => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A192GCM,
                    'bit_length' => 192,
                    'iv_length' => 96,
                    'mac_bit_length' => null
                ],
                'key_management' => [
                    'name' => self::ALGO_DIR,
                    'bit_length' => 192 // Hinzugefügt: Bit-Länge des Schlüssels
                ]
            ],
            self::ALGO_A256GCM => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A256GCM,
                    'bit_length' => 256,
                    'iv_length' => 96,
                    'mac_bit_length' => null
                ],
                'key_management' => [
                    'name' => self::ALGO_DIR,
                    'bit_length' => 256 // Hinzugefügt: Bit-Länge des Schlüssels
                ]
            ],

            // Content Encryption Algorithmen - CBC-HMAC (mit HMAC als Signaturalgorithmus)
            self::ALGO_A128CBC_HS256 => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A128CBC_HS256,
                    'bit_length' => 128,
                    'mac_bit_length' => 256,
                    'hash_algorithm' => 'sha256',
                    'iv_length' => 128
                ],
                'signing_algorithm' => [
                    'name' => 'HS256',
                    'hash_algorithm' => 'sha256'
                ]
            ],
            self::ALGO_A192CBC_HS384 => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A192CBC_HS384,
                    'bit_length' => 192,
                    'mac_bit_length' => 384,
                    'hash_algorithm' => 'sha384',
                    'iv_length' => 128
                ],
                'signing_algorithm' => [
                    'name' => 'HS384',
                    'hash_algorithm' => 'sha384'
                ]
            ],
            self::ALGO_A256CBC_HS512 => [
                'algorithm_type' => 'AES',
                'content_encryption' => [
                    'name' => self::ALGO_A256CBC_HS512,
                    'bit_length' => 256,
                    'mac_bit_length' => 512,
                    'hash_algorithm' => 'sha512',
                    'iv_length' => 128
                ],
                'signing_algorithm' => [
                    'name' => 'HS512',
                    'hash_algorithm' => 'sha512'
                ]
            ]
        ];
    }
}
