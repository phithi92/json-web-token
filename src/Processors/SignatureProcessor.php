<?php

namespace Phithi92\JsonWebToken\Processors;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Cryptographys\OpenSSL\CryptographyProvider;
use Phithi92\JsonWebToken\Cryptographys\HMAC;
use Phithi92\JsonWebToken\Processors\Processor;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\JwtPayload;

/**
 * Class JwsSignatureToken
 *
 * This class provides methods to create and verify JSON Web Signature (JWS) tokens, which are a type
 * of JSON Web Token (JWT) used for securely transmitting signed data between parties.
 *
 * The JwsSignatureToken class supports:
 * - Verifying the structure and signature of a JWS token.
 * - Decoding the Base64 URL-encoded header and payload of the token.
 * - Signing a payload with a specified algorithm and key to create a JWS token.
 *
 * @package Phithi92\JsonWebToken\Processors
 * @author  Phillip Thiele <development@phillip-thiele.de>
 */
class SignatureProcessor extends Processor
{
    public const ALGO_HS256 = 'HS256';
    public const ALGO_HS384 = 'HS384';
    public const ALGO_HS512 = 'HS512';
    public const ALGO_RS256 = 'RS256';
    public const ALGO_RS384 = 'RS384';
    public const ALGO_RS512 = 'RS512';
    public const ALGO_ES256 = 'ES256';
    public const ALGO_ES384 = 'ES384';
    public const ALGO_ES512 = 'ES512';
    public const ALGO_PS256 = 'PS256';
    public const ALGO_PS384 = 'PS384';
    public const ALGO_PS512 = 'PS512';

    private static string $type = 'JWS';

    /**
     * Supported signing algorithms and their configurations.
     *
     * @var array<string, array<mixed>> Supported algorithms with their configurations.
     */
    private static array $supported = [
        'HS256' => [],
        'HS384' => [],
        'HS512' => [],
        'RS256' => [],
        'RS384' => [],
        'RS512' => [],
        'ES256' => [],
        'ES384' => [],
        'ES512' => [],
        'PS256' => [],
        'PS384' => [],
        'PS512' => []
    ];

    public function __construct(JwtAlgorithmManager $manager)
    {
        parent::__construct($manager);
        $this->setProvider(new CryptographyProvider($manager));
    }

    public function getTokenType(): string
    {
        return self::$type;
    }

    /**
     * Decrypts a JWT token and verifies its structure and signature.
     *
     * This method validates the provided token's structure and signature, decodes its payload,
     * and optionally verifies it against a secret key or public key.
     * The verification logic is currently commented out but can be enabled as needed.
     *
     * @param JwtTokenContainer $token The JWT token to decrypt and verify.
     *
     * @return JwtTokenContainer       The verified and decrypted JWT token container.
     */
    public function decrypt(JwtTokenContainer $token): JwtTokenContainer
    {
        $this->verify($token);

        return $token;
    }

    /**
     * Hydrates a JwtTokenContainer from an encoded JWT string.
     *
     * Decodes the JWT string and initializes the appropriate data for a JWS or JWE token.
     *
     * @param  string|array<string> $encodingToken The JWT string to decode and parse.
     * @return JwtTokenContainer The initialized JwtTokenContainer.
     * @throws InvalidFormatException If the token format is incorrect.
     */
    public function parse(string|array $encodingToken): JwtTokenContainer
    {
        if (is_string($encodingToken)) {
            $tokenData = explode('.', $encodingToken);
        } else {
            $tokenData = $encodingToken;
        }

        if (count($tokenData) < 3) {
            throw new InvalidFormatException();
        }

        $headerDecoded = Base64UrlEncoder::decode($tokenData[0], true);
        $payloadDecoded = Base64UrlEncoder::decode($tokenData[1], true);
        $signatureDecoded = Base64UrlEncoder::decode($tokenData[2], true);

        $jwtHeader = JwtHeader::fromJson($headerDecoded);
        $jwtPayload = JwtPayload::fromJson($payloadDecoded);

        $token = (new JwtTokenContainer())
            ->setHeader($jwtHeader)
            ->setPayload($jwtPayload)
            ->setSignature($signatureDecoded);

        return $token;
    }


    /**
     * Signs a payload and generates a JWS token.
     *
     * This method takes a JWT payload, signs it using the specified algorithm and key,
     * and attaches the resulting signature to the token. It supports various algorithms,
     * including RSA, ECDSA, RSA-PSS, and HMAC.
     *
     * @param JwtTokenContainer $token The JWT token to be signed and updated with a signature.
     *
     * @return JwtTokenContainer       The signed JwtTokenContainer with updated header and signature.
     *
     * @throws UnsupportedAlgorithmException If the specified algorithm type is not supported.
     */
    public function encrypt(JwtTokenContainer $token): JwtTokenContainer
    {
        [$algorithmType, $length] = $this->extractAlgorithmComponents($token->getHeader()->getAlgorithm());

        $signatureData = $this->dataToSign($token);
        $signature = '';
        $shaAlgo = 'sha' . $length;
        $processor = $this->getProvider();

        if (
            $algorithmType === CryptographyProvider::ECDSA
            || $algorithmType === CryptographyProvider::RSA_PSS
            || $algorithmType === CryptographyProvider::RSA
        ) {
            $processor->signWithAlgorithm($signatureData, $signature, $shaAlgo);
        } elseif ($algorithmType === CryptographyProvider::HMAC) {
            $signature = (new HMAC\CryptographyProdvider($this->getManager()))->signHmac($signatureData, $shaAlgo);
        } else {
            throw new UnsupportedAlgorithmException($algorithmType);
        }

        $token->setSignature($signature);

        return $token;
    }

    /**
     * Processes the verification of a JWT token's signature based on the specified algorithm type.
     *
     * This method verifies the signature of a JWT token by using the appropriate cryptographic algorithm.
     * It supports various algorithms, including RSA, ECDSA, RSA-PSS, and HMAC.
     *
     * @param JwtTokenContainer $token The JWT token to be verified.
     *
     * @return void                    Throws an exception if verification fails.
     *
     * @throws UnsupportedAlgorithmException If the specified algorithm type is not supported.
     * @throws InvalidSignatureException     If the signature verification fails.
     */
    public function verify(JwtTokenContainer $token): void
    {
        $processor = $this->getProvider();

        // Verify the algorithm type and hash length
        [$algorithmType, $length] = $this->extractAlgorithmComponents($token->getHeader()->getAlgorithm());
        $hashAlgorithm = 'sha' . $length;

        // Combine the header and payload to form the signature input
        $verificationSignatureData = $this->dataToSign($token);

        if (
            $algorithmType === CryptographyProvider::ECDSA
            || $algorithmType === CryptographyProvider::RSA_PSS
            || $algorithmType === CryptographyProvider::RSA
        ) {
            $valid = $processor->verifyWithAlgorithm(
                $verificationSignatureData,
                $token->getSignature(),
                $hashAlgorithm
            );
        } elseif ($algorithmType === CryptographyProvider::HMAC) {
            $valid = (new HMAC\CryptographyProdvider($this->getManager()))->verifyHmac(
                $verificationSignatureData,
                $token->getSignature(),
                $hashAlgorithm
            );
        } else {
            throw new UnsupportedAlgorithmException($algorithmType);
        }

        if ($valid === false) {
            throw new InvalidSignatureException();
        }
    }

    public function assemble(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedPayload = Base64UrlEncoder::encode($token->getPayload()->toJson());
        $encodedSignature = Base64UrlEncoder::encode($token->getSignature());
        return "$encodedHeader.$encodedPayload.$encodedSignature";
    }

    private function dataToSign(JwtTokenContainer $token): string
    {
        $headerJson = $token->getHeader()->toJson();
        $payloadJson = $token->getPayload()->toJson();

        $encodedHeader = Base64UrlEncoder::encode($headerJson);
        $encodedPayload = Base64UrlEncoder::encode($payloadJson);

        // Combine the header and payload to form the signature input
        return "$encodedHeader.$encodedPayload";
    }

    /**
     * Extracts and validates the algorithm type and bit length from the algorithm string.
     *
     * This method parses a given algorithm string (e.g., 'HS256', 'RS512') to extract the algorithm
     * type and bit length. It ensures the format adheres to supported patterns and validates
     * compatibility with known cryptographic standards.
     *
     * @param string $algorithm The algorithm string to be parsed and validated.
     *
     * @return array{string, int}   An array containing:
     *                                  - string $type: The algorithm type ('HS', 'RS', 'ES', 'PS').
     *                                  - int $length: The bit length of the algorithm (256, 384, 512).
     *
     * @throws UnsupportedAlgorithmException If the algorithm format is invalid or unsupported.
     */
    private function extractAlgorithmComponents(string $algorithm): array
    {
        // Ensure the algorithm format is valid (e.g., 'HS256', 'RS512', etc.)
        if (!preg_match('/^(HS|RS|ES|PS)(256|384|512)$/', $algorithm, $matches)) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        return [$matches[1], (int) $matches[2]];
    }

    public static function isSupported(string $algorithm): bool
    {
        return isset(self::$supported[$algorithm]);
    }
}
