<?php

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;
use Phithi92\JsonWebToken\Exception\UnexpectedErrorException;
use Phithi92\JsonWebToken\Token\JwtBase;
use Phithi92\JsonWebToken\Security\Hmac;
use Phithi92\JsonWebToken\Security\Openssl;

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
 * - Requires an instance of the `Openssl` class for cryptographic operations.
 * - Utilizes various exceptions for error handling such as `InvalidArgumentException`.
 *
 * @status Partial (RSA_OAEP is implemented, other algorithms under development)
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class JweEncodingToken extends JwtBase
{
    // Direkte Schlüsselverschlüsselung
    const OPENSSL_DIR = 'dir';

    // RSA Verschlüsselungsalgorithmen
    const OPENSSL_RSA1_5 = 'RSA1_5';
    const OPENSSL_RSA_OAEP = 'RSA-OAEP';
    const OPENSSL_RSA_OAEP_256 = 'RSA-OAEP-256';

    // AES Key Wrap Algorithmen
    const OPENSSL_A128KW = 'A128KW';
    const OPENSSL_A192KW = 'A192KW';
    const OPENSSL_A256KW = 'A256KW';

    // ECDH-ES Key Agreement Algorithmen
    const OPENSSL_ECDH_ES = 'ECDH-ES';
    const OPENSSL_ECDH_ES_A128KW = 'ECDH-ES+A128KW';
    const OPENSSL_ECDH_ES_A192KW = 'ECDH-ES+A192KW';
    const OPENSSL_ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    // ECDH-ES key using P-521
    const OPENSSL_ECDH_ES_P521 = 'ECDH-ES-P521';

    // PBES2 Schlüsselaustauschalgorithmen
    const OPENSSL_PBES2_HS256 = 'PBES2-HS256+A128KW';
    const OPENSSL_PBES2_HS384 = 'PBES2-HS384+A192KW';
    const OPENSSL_PBES2_HS512 = 'PBES2-HS512+A256KW';

    // Inhaltsverschlüsselungsalgorithmen (AES-GCM)
    const OPENSSL_A128GCM = 'A128GCM';
    const OPENSSL_A192GCM = 'A192GCM';
    const OPENSSL_A256GCM = 'A256GCM';


    // Content Encryption Algorithms
    const OPENSSL_AES_256_GCM = 'A256GCM';
    const SODIUM_CHACHA20_POLY1305 = 'chacha20-poly1305';

    // Inhaltsverschlüsselungsalgorithmen (AES-CBC + HMAC)
    const OPENSSL_A128CBC_HS256 = 'A128CBC-HS256';
    const OPENSSL_A192CBC_HS384 = 'A192CBC-HS384';
    const OPENSSL_A256CBC_HS512 = 'A256CBC-HS512';

    const INVALID_INTAGRETY_IV = 'Integrity check failed: IV does not match.';
    const INVALID_ALGORITHM = "Ungültiger JWE-Algorithmus: %s";

    private Openssl $cipher;

    /**
    * Constructor for initializing the cipher object.
    *
    * This method expects an instance of the Openssl class as a parameter.
    * If the provided argument is not an instance of Openssl, an InvalidArgumentException is thrown.
    *
    * @param mixed $cipher The cipher object, expected to be an instance of Openssl.
    * @throws InvalidArgumentException If the provided argument is not an instance of Openssl.
    */
    public function __construct(mixed $cipher)
    {
        // Check if the passed argument is a valid Openssl object
        if (! $cipher instanceof Openssl) {
            throw new InvalidArgumentException('Invalid argument: Expected an instance of Openssl for cipher.');
        }

        $this->cipher = $cipher;
    }

    public function decrypt(array $tokenSignatures, ?string $key = null): array
    {

        // JWE-Token in seine fünf Teile zerlegen: Header, EncryptedKey, IV, Ciphertext, AuthTag
        if (count($tokenSignatures) !== 5) {
            throw new InvalidArgumentException("Invalid JWE token structure.");
        }

        // Base64-url-decode each part
        $header = $tokenSignatures[0]['decoded'];
        $encryptedKey = $tokenSignatures[1]['decoded'];
        $iv = $tokenSignatures[2]['decoded'];
        $ciphertext = $tokenSignatures[3]['decoded'];
        $authTag = $tokenSignatures[4]['decoded'];

        $headerArray = json_decode($header, true);

        if ($headerArray['alg'] !== 'dir') {
            $algorithm = $headerArray['alg'] . '+' . $headerArray['enc'];
        } else {
            $algorithm = $headerArray['enc'];
        }

        $algorithmInfo = $this->extractJweAlgorithmComponents($algorithm);

        if (!isset($algorithmInfo['content_encryption'])) {
            throw new InvalidArgumentException("No content encryption algorithm provided.");
        }

        // Verarbeiten des Key Management Algorithmus
        $decryptedKey = '';
        switch ($algorithmInfo['key_management']['algorithm']) {
            case self::OPENSSL_RSA_OAEP_256:
            case self::OPENSSL_RSA_OAEP:
            case self::OPENSSL_RSA1_5:
                $this->cipher->rsaDecryptWithPrivateKey($encryptedKey, $decryptedKey, OPENSSL_PKCS1_OAEP_PADDING);
                break;

            case self::OPENSSL_A128KW:
            case self::OPENSSL_A192KW:
            case self::OPENSSL_A256KW:
                $decryptedKey = $this->cipher->aesKeyWrapDecrypt($encryptedKey, $key, $algorithmInfo['key_management']['bit_length']);
                break;

            case self::OPENSSL_ECDH_ES_P521: // Verwende die spezifische ECDH-ES P521 Funktion
                $decryptedKey = $this->cipher->decryptWithECDH_ES_P521($encryptedKey, $recipientPrivateKey);
                break;

            case self::OPENSSL_PBES2_HS256:
            case self::OPENSSL_PBES2_HS384:
            case self::OPENSSL_PBES2_HS512:
                $decryptedKey = pbes2DecryptKey($key, $algorithmInfo['key_management']['bit_length']);
                break;

            case self::OPENSSL_DIR:
                $decryptedKey = $encryptedKey;
                break;

            default:
                throw new InvalidArgumentException(sprintf(self::INVALID_ALGORITHM, $algorithmInfo['key_management']['algorithm']));
        }

        // Verarbeiten des Content Encryption Algorithmus
        $contentAlgorithm = $algorithmInfo['content_encryption']['algorithm'];
        $bitLength = $algorithmInfo['content_encryption']['bit_length'];
        $decryptedPayload = null;

        switch ($contentAlgorithm) {
            case self::OPENSSL_A128GCM:
            case self::OPENSSL_A192GCM:
            case self::OPENSSL_A256GCM:
                // GCM-Modus entschlüsseln
                $decryptedPayload = $this->cipher->aesGcmDecrypt($ciphertext, $decryptedKey, $bitLength, $iv, $authTag);
                break;

            case self::OPENSSL_A128CBC_HS256:
            case self::OPENSSL_A192CBC_HS384:
            case self::OPENSSL_A256CBC_HS512:
                $macBitLength = $algorithmInfo['content_encryption']['mac_bit_length'];
                // CBC-Modus mit HMAC entschlüsseln
                if (!verifyHmac($ciphertext, $decryptedKey, $macBitLength, $authTag)) {
                    throw new InvalidArgumentException("Invalid authentication tag (HMAC verification failed).");
                }
                $decryptedPayload = aesCbcHmacDecrypt($ciphertext, $decryptedKey, $bitLength, $iv);
                break;

            default:
                throw new InvalidArgumentException(sprintf(self::INVALID_ALGORITHM, $contentAlgorithm));
        }

        $payloadArray = $this->safeJsonDecode($decryptedPayload);

        return $payloadArray; // Rückgabe der entschlüsselten Payload
    }



    public function createToken(string $payload, string $key, string $algorithm)
    {

        $algorithmInfo = $this->extractJweAlgorithmComponents($algorithm);

        if (!isset($algorithmInfo['content_encryption'])) {
            throw new InvalidArgumentException("No content encryption algorithm provided.");
        }

        $encryptedKey = null;
        $encryptedPayload = null;
        $iv = null;
        $authTag = '';

        $contentKey = openssl_random_pseudo_bytes($algorithmInfo['content_encryption']['bit_length'] / 8); // z.B. 256 Bit für AES-256

        if ($algorithmInfo['key_management'] !== null) {
            // Verarbeiten des Key Management Algorithmus
            switch ($algorithmInfo['key_management']['algorithm']) {
                case self::OPENSSL_RSA_OAEP_256:
                case self::OPENSSL_RSA_OAEP:
                case self::OPENSSL_RSA1_5:
                    $encryptedKey = '';
                    $this->cipher->rsaEncryptWithPublicKey($contentKey, $encryptedKey, OPENSSL_PKCS1_OAEP_PADDING);
                    break;

                case self::OPENSSL_A128KW:
                case self::OPENSSL_A192KW:
                case self::OPENSSL_A256KW:
                    $encryptedKey = $this->cipher->aesKeyWrapEncrypt($contentKey, $algorithmInfo['key_management']['bit_length']);
                    break;

                case self::OPENSSL_ECDH_ES_P521: // Verwende die spezifische ECDH-ES P521 Funktion
                    $encryptedKey = $this->encryptWithECDH_ES_P521($recipientPublicKey, $contentKey);
                    break;

                case self::OPENSSL_ECDH_ES:
                case self::OPENSSL_ECDH_ES_A128KW:
                case self::OPENSSL_ECDH_ES_A192KW:
                case self::OPENSSL_ECDH_ES_A256KW:
                    $encryptedKey = $this->cipher->ecdhEsKeyAgreement();
                    break;

                case self::OPENSSL_PBES2_HS256:
                case self::OPENSSL_PBES2_HS384:
                case self::OPENSSL_PBES2_HS512:
                    $encryptedKey = pbes2EncryptKey($key, $algorithmInfo['key_management']['bit_length']);
                    break;

                case self::OPENSSL_DIR:
                    $encryptedKey = $key;
                    break;

                default:
                    throw new InvalidArgumentException(sprintf(self::INVALID_ALGORITHM, $algorithmInfo['key_management']['algorithm']));
            }
        }

        if ($algorithmInfo['content_encryption'] !== null) {
            // Verarbeiten des Content Encryption Algorithmus
            $contentAlgorithm = $algorithmInfo['content_encryption']['algorithm'];
            $bitLength = $algorithmInfo['content_encryption']['bit_length'];

            switch ($contentAlgorithm) {
                case self::OPENSSL_A128GCM:
                case self::OPENSSL_A192GCM:
                case self::OPENSSL_A256GCM:
                    // GCM benötigt einen IV (Initialisierungsvektor) und erzeugt ein Authentifizierungstag (authTag)
                    $iv = openssl_random_pseudo_bytes(12); // 12 Bytes für GCM
                    $encryptedPayload = $this->cipher->aesGcmEncrypt($payload, $contentKey, $bitLength, $iv, $authTag);
                    break;

                case self::OPENSSL_A128CBC_HS256:
                case self::OPENSSL_A192CBC_HS384:
                case self::OPENSSL_A256CBC_HS512:
                    $macBitLength = $algorithmInfo['content_encryption']['mac_bit_length'];
                    $iv = openssl_random_pseudo_bytes(16); // 16 Bytes für CBC
                    $encryptedPayload = aesCbcHmacEncrypt($payload, $contentKey, $bitLength, $macBitLength, $iv);
                    // Authentifizierungs-Tag für CBC-HMAC (getrenntes HMAC)
                    $authTag = calculateHmac($encryptedPayload, $contentKey, $macBitLength);
                    break;

                default:
                    throw new InvalidArgumentException(sprintf(self::INVALID_ALGORITHM, $contentAlgorithm));
            }
        }

        // JWE Header erstellen
        $header = json_encode([
            'alg' => $algorithmInfo['key_management']['algorithm'],
            'enc' => $algorithmInfo['content_encryption']['algorithm']
        ]);

        // JWE Token zusammenstellen (5 Teile: Header.EncryptedKey.IV.Ciphertext.AuthTag)
        $jweToken = base64_encode($header) . '.' .
                    base64_encode($encryptedKey) . '.' .
                    base64_encode($iv) . '.' .
                    base64_encode($encryptedPayload) . '.' .
                    base64_encode($authTag);

        return $jweToken; // Rückgabe des vollständigen JWE Tokens
    }



    /**
     * Creates a JWE (JSON Web Encryption) token by encrypting the payload
     * and optionally encrypting the CEK (Content Encryption Key).
     *
     * @param string $payload The payload (data content) to be encrypted.
     * @param string $key The secret key or public key for encryption (depends on the algorithm).
     * @param string $algorithm The algorithm.
     *
     * @return string The encoded JWE token.
     *
     * @throws InvalidArgumentException If required algorithm data is missing.
     * @throws InvalidTokenException If CEK encryption fails.
     * @throws Exception If random byte generation or payload encryption fails.
     */
    public function ccreateToken(string $payload, string $key, string $algorithm): string
    {
        $algorithm_data = $this->getAlgorithmData($algorithm);

        // Cipher and initialization variables
        $cipher = $algorithm_data['cipher'];
        $tag = ''; // Tag for authentication (used if HMAC is enabled)
        $length_bytes = (int) $algorithm_data['key_length'] / 8; // Convert key length from bits to bytes
        $iv_length = (int) $algorithm_data['iv_length']; // Initialization vector length (IV)

        $cek = random_bytes($length_bytes);

        // Check if OpenSSL algorithm is provided
        if (isset($algorithm_data['openssl_algo'])) {
            $cek = random_bytes($length_bytes / 8);

            $padding = $algorithm_data['openssl_algo'];

            // Optional: Bestimme den AES-Schlüssel unabhängig vom CEK
            $aes_key = random_bytes($length_bytes / 8); // 32 Bytes für AES-256-Schlüssel

            $encrypted_cek = ''; // Store encrypted data when used

            $this->cipher->rsaEncryptWithPublicKey($cek, $encrypted_cek, $padding);
        }

        // If HMAC tag length is defined, derive the AES key and HMAC key from the CEK
        if (isset($algorithm_data['tag_length'])) {
            // Generate the CEK (Content Encryption Key) with random bytes
            $halfTokenLength = strlen($cek) / 2;
            $aes_key = substr($cek, 0, $halfTokenLength); // First half for AES key
            $hmac_key = substr($cek, $halfTokenLength);   // Second half for HMAC key
        }

        // Encrypt the payload using AES (or another algorithm) and the IV
        $iv = random_bytes($iv_length); // Generate a random initialization vector (IV)

        $cipher_payload = '';

        // tag wird als refferenz übergeben sowie cipherPayload
        $this->cipher->encryptWithPassphrase($payload, $cipher_payload, $cipher, $aes_key, $iv, $tag);

        // Encode the header (typically contains algorithm metadata)
        $header = json_encode($algorithm_data['header']);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new UnexpectedErrorException('Header encoding failed: ' . json_last_error_msg());
        }

        // If HMAC is used, generate the authentication signature
        if (isset($hmac_key)) {
            $hash = $algorithm_data['hmac_algo']; // HMAC algorithm (e.g., SHA256)

            $signature = $this->buildAndEncodeToken([$header, $iv, $cipher_payload]);

            $tag = (new Hmac())->signHmac($signature, $hmac_key, $algorithm_data['hmac_algo'], $signature);
        }

        if (empty($tag)) {
            throw new UnexpectedErrorException('Token build faild. No tag found');
        }

        // Build the token in the correct format, including the encrypted CEK if necessary
        $token_array = isset($hmac_key)
            ? [$header, $iv, $cipher_payload, $tag]
            : [$header, $encrypted_cek, $iv, $cipher_payload, $tag];

        // Return the final encoded token
        return $this->buildAndEncodeToken($token_array);
    }

    private function extractJweAlgorithmComponents(string $jweAlgorithm)
    {
        $config = $this->getJweAlgorithmConfiguration();

        // Prüfen, ob der Algorithmus in der Konfiguration vorhanden ist
        if (!isset($config[$jweAlgorithm])) {
            throw new \Phithi92\JsonWebToken\Exception\InvalidArgumentException("Invalid JWE Algorithm: " . $jweAlgorithm);
        }

        $keyManagementAlgorithm = $config[$jweAlgorithm]['key_management'] ?? null;
        $contentEncryptionAlgorithm = $config[$jweAlgorithm]['content_encryption'] ?? null;

        // Es muss entweder ein Key Management Algorithmus oder ein Content Encryption Algorithmus vorhanden sein
        if (!$keyManagementAlgorithm && !$contentEncryptionAlgorithm) {
            throw new \Phithi92\JsonWebToken\Exception\InvalidArgumentException("Algorithm must have either Key Management or Content Encryption.");
        }

        // Rückgabe der extrahierten Komponenten
        return [
            'key_management' => $keyManagementAlgorithm ? [
                'algorithm' => $keyManagementAlgorithm['name'],
                'bit_length' => $keyManagementAlgorithm['bit_length']
            ] : null,
            'content_encryption' => $contentEncryptionAlgorithm ? [
                'algorithm' => $contentEncryptionAlgorithm['name'],
                'bit_length' => $contentEncryptionAlgorithm['bit_length'],
                'mac_bit_length' => $contentEncryptionAlgorithm['mac_bit_length']
            ] : null
        ];
    }

    private function getJweAlgorithmConfiguration(): array
    {
        return [
            // RSA Key Management Algorithmen
            self::OPENSSL_RSA_OAEP => [
                'key_management' => ['name' => self::OPENSSL_RSA_OAEP, 'bit_length' => null],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_RSA_OAEP_256 => [
                'key_management' => ['name' => self::OPENSSL_RSA_OAEP_256, 'bit_length' => null],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_RSA1_5 => [
                'key_management' => ['name' => self::OPENSSL_RSA1_5, 'bit_length' => null],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],

            // ECDH-ES Key Management Algorithmen mit AES Key Wrap
            self::OPENSSL_ECDH_ES_A128KW => [
                'key_management' => ['name' => self::OPENSSL_ECDH_ES_A128KW, 'bit_length' => 128],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_ECDH_ES_A192KW => [
                'key_management' => ['name' => self::OPENSSL_ECDH_ES_A192KW, 'bit_length' => 192],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_ECDH_ES_A256KW => [
                'key_management' => ['name' => self::OPENSSL_ECDH_ES_A256KW, 'bit_length' => 256],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],

            // Passwortbasierte Algorithmen (PBES2)
            self::OPENSSL_PBES2_HS256 => [
                'key_management' => ['name' => self::OPENSSL_PBES2_HS256, 'bit_length' => 128],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_PBES2_HS384 => [
                'key_management' => ['name' => self::OPENSSL_PBES2_HS384, 'bit_length' => 192],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_PBES2_HS512 => [
                'key_management' => ['name' => self::OPENSSL_PBES2_HS512, 'bit_length' => 256],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],

            // AES Key Wrap Algorithmen (ohne Key Agreement)
            self::OPENSSL_A128KW => [
                'key_management' => ['name' => self::OPENSSL_A128KW, 'bit_length' => 128],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_A192KW => [
                'key_management' => ['name' => self::OPENSSL_A192KW, 'bit_length' => 192],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],
            self::OPENSSL_A256KW => [
                'key_management' => ['name' => self::OPENSSL_A256KW, 'bit_length' => 256],
                'content_encryption' => ['name' =>  self::OPENSSL_DIR]
            ],

            // Content Encryption Algorithmen - GCM
            self::OPENSSL_A128GCM => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A128GCM, 'bit_length' => 128, 'mac_bit_length' => null]
            ],
            self::OPENSSL_A192GCM => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A192GCM, 'bit_length' => 192, 'mac_bit_length' => null]
            ],
            self::OPENSSL_A256GCM => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A256GCM, 'bit_length' => 256, 'mac_bit_length' => null]
            ],

            // Content Encryption Algorithmen - CBC-HMAC
            self::OPENSSL_A128CBC_HS256 => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A128CBC_HS256, 'bit_length' => 128, 'mac_bit_length' => 256]
            ],
            self::OPENSSL_A192CBC_HS384 => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A192CBC_HS384, 'bit_length' => 192, 'mac_bit_length' => 384]
            ],
            self::OPENSSL_A256CBC_HS512 => [
                'key_management' => ['name' =>  self::OPENSSL_DIR],
                'content_encryption' => ['name' => self::OPENSSL_A256CBC_HS512, 'bit_length' => 256, 'mac_bit_length' => 512]
            ],

            // Kombinationen von Key Management und Content Encryption
            self::OPENSSL_RSA_OAEP . '+' . self::OPENSSL_A128GCM => [
                'key_management' => ['name' => self::OPENSSL_RSA_OAEP, 'bit_length' => null],
                'content_encryption' => ['name' => self::OPENSSL_A128GCM, 'bit_length' => 128, 'mac_bit_length' => null]
            ],
            self::OPENSSL_RSA_OAEP . '+' . self::OPENSSL_A192GCM => [
                'key_management' => ['name' => self::OPENSSL_RSA_OAEP, 'bit_length' => null],
                'content_encryption' => ['name' => self::OPENSSL_A192GCM, 'bit_length' => 192, 'mac_bit_length' => null]
            ],
            self::OPENSSL_RSA_OAEP . '+' . self::OPENSSL_A256GCM => [
                'key_management' => ['name' => self::OPENSSL_RSA_OAEP, 'bit_length' => null],
                'content_encryption' => ['name' => self::OPENSSL_A256GCM, 'bit_length' => 256, 'mac_bit_length' => null]
            ],
            self::OPENSSL_RSA1_5 . '+' . self::OPENSSL_A128GCM => [
                'key_management' => ['name' => self::OPENSSL_RSA1_5, 'bit_length' => null],
                'content_encryption' => ['name' => self::OPENSSL_A128GCM, 'bit_length' => 128, 'mac_bit_length' => null]
            ]
        ];
    }
}
