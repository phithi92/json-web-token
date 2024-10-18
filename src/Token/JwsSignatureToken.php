<?php

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exception\InvalidArgumentException;
use Phithi92\JsonWebToken\Exception\InvalidTokenException;
use Phithi92\JsonWebToken\Exception\UnexpectedErrorException;
use Phithi92\JsonWebToken\Token\JwtBase;
use Phithi92\JsonWebToken\Security\Hmac;
use Phithi92\JsonWebToken\Security\Openssl;

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
 * Supported algorithms:
 * - HS256, HS384, HS512 (HMAC with SHA-256/384/512)
 * - RS256, RS384, RS512 (RSA with SHA-256/384/512)
 * - ES256, ES384, ES512 (ECDSA with SHA-256/384/512)
 * - PS256, PS384, PS512 (RSASSA-PSS with SHA-256/384/512)
 *
 * ### Implemented Standards:
 * 1. **RFC 7519 - JSON Web Token (JWT)**:
 *    - This class conforms to the JWT specification as outlined in [RFC 7519]( https://datatracker.ietf.org/doc/rfc7519 ).
 *    - JWT is a compact, URL-safe means of representing claims to be transferred between two parties.
 *
 * 2. **RFC 7515 - JSON Web Signature (JWS)**:
 *    - The class implements the JWS standard, as defined in [RFC 7515]( https://datatracker.ietf.org/doc/rfc7515 ),
 *      which describes mechanisms for integrity protection through digital signatures and HMACs.
 *
 * 3. **RFC 4648 - Base64 URL encoding**:
 *    - The tokens are encoded and decoded using Base64 URL encoding as described in [RFC 4648]( https://datatracker.ietf.org/doc/rfc4648 ),
 *      ensuring URL-safe transmission of the token's header, payload, and signature.
 *
 * Example usage:
 *
 * // Create a token
 * $jwsToken = new JwsToken();
 * $token = $jwsToken->createToken($payloadJson, $secret, 'HS256');
 *
 * // Verify and decrypt a token
 * $payload = $jwsToken->decrypt($tokenParts, $key);
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class JwsSignatureToken extends JwtBase
{
    const ERROR_HEADER_INVALID_DATA = 'Invalid header data.';
    const ERROR_TOKEN_INVALID_STRUCTURE = 'Invalid token structure.';
    const ERROR_TOKEN_INVALID_CHAR = 'Token contains invalid characters.';
    const ERROR_SECRET_EMPTY = 'Key cannot be empty';
    const ERROR_SECRET_INVALID_LENGTH = 'Secret key is too short. Minimum length is 32 characters.';

    public function __construct(private Openssl $openssl)
    {
        ;
    }

    public function getOpenssl(): Openssl
    {
        return $this->openssl;
    }

    /**
     * Verifies the structure and signature of a JWS token, and decodes its payload.
     *
     * @param array  $tokenSegments  Array containing the token's header, payload, and signature segments.
     * @param string $secret            Secret (HMAC) or public key (RSA) for signature verification.
     *
     * @return array The decoded payload if verification is successful.
     *
     * @throws InvalidTokenException If the token structure or signature is invalid.
     * @throws InvalidArgumentException If the key is empty or the token contains invalid characters.
     */
    public function decrypt(array $tokenSegments, string $secret): array
    {
        // Ensure the token has exactly 3 segments (header, payload, signature)
        if (count($tokenSegments) !== 3) {
            throw new InvalidTokenException(self::ERROR_TOKEN_INVALID_STRUCTURE);
        }

        if (empty($secret)) {
            throw new InvalidArgumentException(self::ERROR_SECRET_EMPTY);
        }

        // Validating each token segment (Header, Payload, Signature)
        foreach ($tokenSegments as $segment) {
            if (!preg_match('/^[A-Za-z0-9\-_]+$/', $segment['encoded'])) {
                throw new InvalidTokenException(self::ERROR_TOKEN_INVALID_CHAR);
            }
        }

        $headerSegment = $tokenSegments[0];
        $payloadSegment = $tokenSegments[1];
        $signatureSegment = $tokenSegments[2];

        $decodedHeader = $this->safeJsonDecode($headerSegment['decoded']);

        if (!isset($decodedHeader['alg'])) {
            throw new InvalidTokenException(self::ERROR_HEADER_INVALID_DATA);
        }

        // Extract algorithm from header and validate it
        $decodedPayload = $this->safeJsonDecode($payloadSegment['decoded']);

        $algorithm = $decodedHeader['alg'];

        // Verify the algorithm type and hash length
        [$algorithmType, $length] = $this->extractAlgorithmComponents($algorithm);
        $hashAlgorithm = 'sha' . $length;

        // Combine the header and payload to form the signature input
        $signatureData = $headerSegment['encoded'] . '.' . $payloadSegment['encoded'];

        $decodedSignature = $signatureSegment['decoded'];

        $this->processSignature($algorithmType, $signatureData, $secret, $hashAlgorithm, $decodedSignature);

        return $decodedPayload;
    }

    /**
     * Signs a payload and generates a JWS token.
     *
     * @param string $payloadJson The payload to be signed, in JSON format.
     * @param string $secret      Secret key (HMAC) or private key (RSA) used for signing.
     * @param string $algorithm   The signing algorithm (e.g., 'HS256', 'RS512').
     *
     * @return string The generated JWS token (Base64 URL-encoded).
     *
     * @throws InvalidArgumentException If the algorithm is unsupported, the payload is invalid, or the key is too short.
     * @throws InvalidTokenException    If token creation fails.
     */
    public function createToken(string $payloadJson, string $secret, string $algorithm): string
    {
        if (empty($secret)) {
            throw new InvalidArgumentException(self::ERROR_SECRET_EMPTY);
        }

        [$algorithmType, $length] = $this->extractAlgorithmComponents($algorithm);

        $header = ['alg' => $algorithm];

        $headerJson = $this->safeJsonEncode($header);

        $signatureData = $this->buildAndEncodeToken([$headerJson, $payloadJson]);
        $signature = '';
        $shaAlgo = 'sha' . $length;

        $this->processSignature($algorithmType, $signatureData, $secret, $shaAlgo, null, $signature);

        $encodedData = $this->buildAndEncodeToken([$headerJson, $payloadJson, $signature]);

        return $encodedData;
    }

    /**
     * Extracts and validates the algorithm type and bit length from the algorithm string.
     *
     * @param string $algorithm The algorithm (e.g., 'HS256', 'RS512').
     *
     * @return array An array containing the algorithm type ('HS', 'RS', etc.) and the bit length (256, 384, 512).
     *
     * @throws InvalidArgumentException If the algorithm format is invalid.
     */
    private function extractAlgorithmComponents(string $algorithm): array
    {
        // Ensure the algorithm format is valid (e.g., 'HS256', 'RS512', etc.)
        if (!preg_match('/^(HS|RS|ES|PS)(256|384|512)$/', $algorithm, $matches)) {
            throw new InvalidArgumentException(sprintf(self::ERROR_ALGORITHM_UNSUPPORTED, $algorithm));
        }

        $algorithmType = $matches[1];
        $hashLength = $matches[2];

        return [$algorithmType, $hashLength];
    }

    /**
    * Processes the signature based on the specified algorithm type.
    *
    * Depending on the algorithm and whether a signature is provided or not,
    * this function either signs the given data or verifies the provided signature.
    *
    * Supported algorithms:
    *  - ECDSA: Elliptic Curve Digital Signature Algorithm
    *  - RSA_PSS: RSA Probabilistic Signature Scheme
    *  - RSA: Rivest–Shamir–Adleman algorithm
    *  - HMAC: Hash-based Message Authentication Code
    *
    * @param string $algorithmType The type of algorithm to be used (ECDSA, RSA_PSS, RSA, HMAC).
    * @param string $signatureData The data to be signed or verified.
    * @param string $secret The secret or key for the signing/verifying process.
    * @param string $hashAlgorithm The hash algorithm to use (e.g., SHA256).
    * @param string|null $decodedSignature The signature to verify (if applicable).
    * @param string|null &$signature The variable to store the generated signature (if applicable).
    *
    * @throws InvalidArgumentException if the algorithm type is unsupported.
    */
    private function processSignature(
        string $algorithmType,
        string $signatureData,
        string $secret,
        string $hashAlgorithm,
        ?string $decodedSignature = null,
        ?string &$signature = null
    ): void {
        $openssl = $this->getOpenssl();

        switch ($algorithmType) {
            case Openssl::ECDSA:
                if ($signature === null) {
                    $openssl->verifyEcdsa($signatureData, $decodedSignature, $secret, $hashAlgorithm);
                } else {
                    $openssl->signEcdsa($signatureData, $signature, $hashAlgorithm, $secret);
                }
                break;
            case Openssl::RSA_PSS:
                if ($signature === null) {
                    $openssl->verifyRsaPss($signatureData, $decodedSignature, $secret, $hashAlgorithm);
                } else {
                    $openssl->signRsaPss($signatureData, $signature, $hashAlgorithm, $secret);
                }
                break;
            case Openssl::RSA:
                if ($signature === null) {
                    $openssl->verifyRsa($signatureData, $decodedSignature, $secret, $hashAlgorithm);
                } else {
                    $openssl->signRsa($signatureData, $signature, $hashAlgorithm, $secret);
                }
                break;
            case Openssl::HMAC:
                if ($signature === null) {
                    (new Hmac())->verifyHmac($signatureData, $decodedSignature, $hashAlgorithm, $secret);
                } else {
                    $signature = (new Hmac())->signHmac($signatureData, $hashAlgorithm, $secret);
                }
                break;
            default:
                throw new InvalidArgumentException(sprintf(self::ERROR_ALGORITHM_UNSUPPORTED, $algorithmType));
        }
    }
}
