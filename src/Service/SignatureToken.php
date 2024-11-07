<?php

namespace Phithi92\JsonWebToken\Service;

use Phithi92\JsonWebToken\Cryptography\OpenSSL\CryptoManager;
use Phithi92\JsonWebToken\Cryptography\HMAC;
use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Exception\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\UnsupportedAlgorithmException;

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
 *    - This class conforms to the JWT specification as outlined in
 *      [RFC 7519]( https://datatracker.ietf.org/doc/rfc7519 ).
 *    - JWT is a compact, URL-safe means of representing claims to be transferred between two parties.
 *
 * 2. **RFC 7515 - JSON Web Signature (JWS)**:
 *    - The class implements the JWS standard, as defined in [RFC 7515]( https://datatracker.ietf.org/doc/rfc7515 ),
 *      which describes mechanisms for integrity protection through digital signatures and HMACs.
 *
 * 3. **RFC 4648 - Base64 URL encoding**:
 *    - The tokens are encoded and decoded using Base64 URL encoding as
 *      described in [RFC 4648]( https://datatracker.ietf.org/doc/rfc4648 ),
 *      ensuring URL-safe transmission of the token's header, payload, and signature.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class SignatureToken
{
    private JwtAlgorithmManager $algorithmManager;
    private CryptoManager $openssl;

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

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->algorithmManager = $manager;
        $this->openssl = new CryptoManager($manager);
    }

    public function getOpenssl(): CryptoManager
    {
        return $this->openssl;
    }

    /**
     * Verifies the structure and signature of a JWS token, and decodes its payload.
     *
     * @param array  $tokenSegments Array containing the token's header, payload, and signature segments.
     * @param string $secret        Secret (HMAC) or public key (RSA) for signature verification.
     *
     * @return array The decoded payload if verification is successful.
     *
     * @throws InvalidToken If the token structure or signature is invalid.
     * @throws InvalidArgument If the key is empty or the token contains invalid characters.
     */
    public function decrypt(JwtTokenContainer $token): JwtTokenContainer
    {

        if (! $this->verify($token)) {
            throw new InvalidSignatureException();
        }

        return $token;
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
     * @throws InvalidArgument If the algorithm is unsupported, the payload is
     *         invalid, or the key is too short.
     * @throws InvalidToken    If token creation fails.
     */
    public function create(JwtTokenContainer $token): JwtTokenContainer
    {
        $token->setHeader(new JwtHeader($this->algorithmManager));

        [$algorithmType, $length] = $this->extractAlgorithmComponents($token->getHeader()->getAlgorithm());

        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedPayload = Base64UrlEncoder::encode($token->getPayload()->toJson());

        $signatureData = "$encodedHeader.$encodedPayload";
        $signature = '';
        $shaAlgo = 'sha' . $length;

        $this->processSignature(
            $algorithmType,
            $signatureData,
            $shaAlgo,
            null,
            $signature
        );

        $token->setSignature($signature);

        return $token;
    }

    /**
     * Extracts and validates the algorithm type and bit length from the algorithm string.
     *
     * @param string $algorithm The algorithm (e.g., 'HS256', 'RS512').
     *
     * @return array An array containing the algorithm type ('HS', 'RS', etc.) and the bit length (256, 384, 512).
     *
     * @throws InvalidArgument If the algorithm format is invalid.
     */
    private function extractAlgorithmComponents(string $algorithm): array
    {
        // Ensure the algorithm format is valid (e.g., 'HS256', 'RS512', etc.)
        if (!preg_match('/^(HS|RS|ES|PS)(256|384|512)$/', $algorithm, $matches)) {
            throw UnsupportedAlgorithmException($algorithm);
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
     * @param string      $algorithmType    The type of algorithm to be used (ECDSA, RSA_PSS, RSA, HMAC).
     * @param string      $signatureData    The data to be signed or verified.
     * @param string      $secret           The secret or key for the signing/verifying process.
     * @param string      $hashAlgorithm    The hash algorithm to use (e.g., SHA256).
     * @param string|null $decodedSignature The signature to verify (if applicable).
     * @param string|null &$signature       The variable to store the generated signature (if applicable).
     *
     * @throws InvalidArgument if the algorithm type is unsupported.
     */
    public function verify(JwtTokenContainer $token): bool
    {
        $openssl = $this->getOpenssl();

        // Verify the algorithm type and hash length
        [$algorithmType, $length] = $this->extractAlgorithmComponents($token->getHeader()->getAlgorithm());
        $hashAlgorithm = 'sha' . $length;

        $headerJson = $token->getHeader()->toJson();
        $payloadJson = $token->getPayload()->toJson();

        $encodedHeader = Base64UrlEncoder::encode($headerJson);
        $encodedPayload = Base64UrlEncoder::encode($payloadJson);

        // Combine the header and payload to form the signature input
        $signatureData = "$encodedHeader.$encodedPayload";

        if (
            $algorithmType === CryptoManager::ECDSA
            || $algorithmType === CryptoManager::RSA_PSS
            || $algorithmType === CryptoManager::RSA
        ) {
            return $openssl->verifyWithAlgorithm($signatureData, $token->getSignature(), $hashAlgorithm);
        } elseif ($algorithmType === CryptoManager::HMAC) {
            return (new HMAC\CryptoManager())->verifyHmac(
                $signatureData,
                $token->getSignature(),
                $hashAlgorithm,
                $this->algorithmManager->getPassphrase()
            );
        } else {
            throw new UnsupportedAlgorithmException($algorithmType);
        }
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
     * @param string      $algorithmType    The type of algorithm to be used (ECDSA, RSA_PSS, RSA, HMAC).
     * @param string      $signatureData    The data to be signed or verified.
     * @param string      $secret           The secret or key for the signing/verifying process.
     * @param string      $hashAlgorithm    The hash algorithm to use (e.g., SHA256).
     * @param string|null $decodedSignature The signature to verify (if applicable).
     * @param string|null &$signature       The variable to store the generated signature (if applicable).
     *
     * @throws InvalidArgument if the algorithm type is unsupported.
     */
    private function processSignature(
        string $algorithmType,
        string $signatureData,
        string $hashAlgorithm,
        ?string $decodedSignature = null,
        ?string &$signature = null
    ): void {
        $openssl = $this->getOpenssl();

        if (
            $algorithmType === CryptoManager::ECDSA
            || $algorithmType === CryptoManager::RSA_PSS
            || $algorithmType === CryptoManager::RSA
        ) {
            $openssl->signWithAlgorithm($signatureData, $signature, $hashAlgorithm);
        } elseif ($algorithmType === CryptoManager::HMAC) {
            $signature = (new HMAC\CryptoManager())->signHmac(
                $signatureData,
                $hashAlgorithm,
                $this->algorithmManager->getPassphrase()
            );
        } else {
            throw new UnsupportedAlgorithmException($algorithmType);
        }
    }
}
