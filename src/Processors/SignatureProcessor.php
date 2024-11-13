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
 * @author Phillip Thiele <development@phillip-thiele.de>
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

    private static $type = 'JWS';

    // List of supported JWS algorithms
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
     * Verifies the structure and signature of a JWS token, and decodes its payload.
     *
     * @param array  $tokenSegments Array containing the token's header, payload, and signature segments.
     * @param string $secret        Secret (HMAC) or public key (RSA) for signature verification.
     *
     * @return JwtTokenContainer The decoded payload if verification is successful.
     *
     * @throws InvalidSignatureException If the token signature is invalid.
     * @throws InvalidTokenStructure If the token structure is invalid
     * @throws InvalidArgument If the key is empty or the token contains invalid characters.
     */
    public function decrypt(JwtTokenContainer $token): JwtTokenContainer
    {
//        $this->verify($token);

        return $token;
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

        if (count($tokenData) < 3) {
            throw new InvalidFormatException();
        }

        $headerDecoded = Base64UrlEncoder::decode($tokenData[0]);
        $payloadDecoded = Base64UrlEncoder::decode($tokenData[1]);
        $signatureDecoded = Base64UrlEncoder::decode($tokenData[2]);

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
     * @param string $payloadJson The payload to be signed, in JSON format.
     * @param string $secret      Secret key (HMAC) or private key (RSA) used for signing.
     * @param string $algorithm   The signing algorithm (e.g., 'HS256', 'RS512').
     *
     * @return JwtTokenContainer The initialized JwtTokenContainer.
     *
     * @throws InvalidArgument If the algorithm is unsupported, the payload is
     *         invalid, or the key is too short.
     */
    public function encrypt(JwtTokenContainer $token): JwtTokenContainer
    {
        $token->setHeader(new JwtHeader($this->getManager()->getAlgorithm(), $this->getManager()->getTokenType()));

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
            $signature = (new HMAC\CryptographyProdvider($this->getManager()))->signHmac(
                $signatureData,
                $shaAlgo,
                $this->getManager()->getPassphrase()
            );
        } else {
            throw new UnsupportedAlgorithmException($algorithmType);
        }

        $token->setSignature($signature);

        return $token;
    }

    /**
     * Processes the signature based on the specified algorithm type.
     *
     * Depending on the algorithm and whether a signature is provided or not,
     * this function either signs the given data or verifies the provided signature.
     *
     * @param string      $algorithmType    The type of algorithm to be used (ECDSA, RSA_PSS, RSA, HMAC).
     * @param string      $verificationSignatureData    The data to be signed or verified.
     * @param string      $secret           The secret or key for the signing/verifying process.
     * @param string      $hashAlgorithm    The hash algorithm to use (e.g., SHA256).
     * @param string|null $decodedSignature The signature to verify (if applicable).
     * @param string|null &$signature       The variable to store the generated signature (if applicable).
     *
     * @throws InvalidArgument if the algorithm type is unsupported.
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
                $hashAlgorithm,
                $this->getManager()->getPassphrase()
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

        return [$matches[1], (int) $matches[2]];
    }

    public static function isSupported(string $algorithm): bool
    {
        return isset(self::$supported[$algorithm]);
    }
}
