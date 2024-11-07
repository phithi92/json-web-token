<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Service\SignatureToken;
use Phithi92\JsonWebToken\Service\EncodingToken;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Exception\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exception\Token\InvalidFormatException;

/**
 * JsonWebToken is a final class responsible for creating, validating,
 * and managing JSON Web Tokens (JWTs), including JWS (JSON Web Signature)
 * and JWE (JSON Web Encryption) types. It supports token generation,
 * algorithm selection, and encoding/decoding of JWT structures.
 *
 * Note: The token structure is validated within this class, while the
 * content of the payload itself is validated only when the `toArray`
 * method of the JwtTokenContainer class is called.
 *
 * Key functionalities include:
 * - Creating JWTs (JWS or JWE) with support for various algorithms.
 * - Handling Base64URL encoding and decoding for JWT components.
 *
 * This class enforces the JWT standards RFC 7515 (JWS) and RFC 7516 (JWE),
 * and utilizes OpenSSL for cryptographic operations. It throws exceptions for
 * malformed tokens or cryptographic errors.
 *
 * @throws Specific exceptions provide clear messages for JWT-related issues.
 *
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtTokenFactory
{
    /**
     * Initializes the JwtTokenFactory with a JwtAlgorithmManager instance.
     *
     * @param JwtAlgorithmManager $cipher The algorithm manager for token encryption/decryption.
     */
    public function __construct(private JwtAlgorithmManager $cipher)
    {
    }

    /**
     * Creates a JSON Web Token (JWT) using the provided payload.
     *
     * Determines if the token should be a JWS (signed) or JWE (encrypted),
     * and constructs the token accordingly.
     *
     * @param  JwtPayload $payload The data to encode within the JWT payload.
     * @return string The generated JWT string.
     */
    public function create(JwtPayload $payload): string
    {
        $token = new JwtTokenContainer($payload);
        $token->setHeader(new JwtHeader($this->cipher));

        $manager = $this->initializeTokenManager($token, $this->cipher);

        $tokenContainer = $manager->create($token);

        return $this->generateToken($tokenContainer);
    }

    /**
     * Generates the final JWT string by encoding and concatenating the token parts.
     *
     * Uses different encoding methods depending on the token type (JWS or JWE).
     *
     * @param  JwtTokenContainer $token The token container with the token's data.
     * @return string The complete JWT string.
     */
    public function generateToken(JwtTokenContainer $token): string
    {
        $type = $token->getHeader()->getType();

        if ($type === 'JWS') {
            return $this->generateJwsToken($token);
        } elseif ($type === 'JWE') {
            return $this->generateJweToken($token);
        } else {
            throw new UnsupportedTokenTypeException($type);
        }
    }

    /**
     * Decrypts a JWT string into a JwtTokenContainer object.
     *
     * Decrypts and verifies the JWT based on its type (JWS or JWE),
     * throwing an exception if verification fails.
     *
     * @param  string $encodingToken The encoded JWT string to decrypt.
     * @return JwtTokenContainer The decrypted token container object.
     * @throws InvalidSignatureException If the token's signature is invalid.
     */
    public function decrypt(string $encodingToken): JwtTokenContainer
    {
        $token = $this->hydrateJwtContainerFromString($encodingToken);

        $manager = $this->initializeTokenManager($token, $this->cipher);

        $manager->decrypt($token);

        if (! $manager->verify($token)) {
            throw new InvalidSignatureException();
        }

        return $token;
    }

    /**
     * Refreshes an existing JWT by updating its expiration.
     *
     * Decrypts the token, updates its issuance and expiration times,
     * then re-generates the JWT.
     *
     * @param  string $encodingToken      The encoded JWT string to refresh.
     * @param  string $expirationInterval The interval for the new expiration time.
     * @return string The refreshed JWT string.
     */
    public function refresh(string $encodingToken, string $expirationInterval = '+1 hour'): string
    {
        $token = $this->decrypt($encodingToken);

        $token->getPayload()->setIssuedAt($expirationInterval);
        $token->getPayload()->setExpiration($expirationInterval);

        return $this->create($token->getPayload());
    }

    /**
     * Static method to refresh a JWT token with a new expiration interval.
     *
     * This method creates a new instance of the class using the specified
     * JWT algorithm manager and calls the instance method `refresh`.
     * It returns a refreshed JWT with an updated expiration interval.
     *
     * @param  JwtAlgorithmManager $algorithm          The algorithm manager for handling token operations.
     * @param  string              $encodingToken      The existing encoded JWT token to be refreshed.
     * @param  string              $expirationInterval The new expiration interval for the refreshed token.
     * @return string                                  The refreshed JWT token with updated expiration.
     */
    public static function refreshToken(
        JwtAlgorithmManager $algorithm,
        string $encodingToken,
        string $expirationInterval
    ): string {
        return (new self($algorithm))->refresh($encodingToken, $expirationInterval);
    }

    /**
     * Static factory method to generate a JWT using a specified algorithm.
     *
     * @param  JwtAlgorithmManager $algorithm The algorithm manager for encoding.
     * @param  JwtPayload          $payload   The payload data for the token.
     * @return string The generated JWT string.
     */
    public static function createToken(JwtAlgorithmManager $algorithm, JwtPayload $payload): string
    {
        return (new self($algorithm))->create($payload);
    }

    /**
     * Static factory method to generate a JWT using a specified algorithm.
     *
     * @param  JwtAlgorithmManager $algorithm The algorithm manager for encoding.
     * @param  string              $encodedToken   The encoded token string.
     * @return string The generated JWT string.
     */
    public static function decryptToken(JwtAlgorithmManager $algorithm, string $encodedToken): JwtTokenContainer
    {
        return (new self($algorithm))->decrypt($encodedToken);
    }

    private function initializeTokenManager(JwtTokenContainer $token, JwtAlgorithmManager $manager)
    {
        $type = $token->getHeader()->getType();

        if ($type === 'JWS') {
            return new SignatureToken($manager);
        } elseif ($type === 'JWE') {
            return new EncodingToken($manager);
        } else {
            throw new Exception\Token\InvalidFormatException();
        }
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
    private function hydrateJwtContainerFromString(string $encodingToken): JwtTokenContainer
    {
        $tokenData = explode('.', $encodingToken);

        if (count($tokenData) < 3) {
            throw new InvalidFormatException();
        }

        $headerDecoded = Base64UrlEncoder::decode($tokenData[0]);
        $jwtHeader = JwtHeader::fromJson($headerDecoded);

        $token = (new JwtTokenContainer())->setHeader($jwtHeader);
        $type = $token->getHeader()->getType();

        if ($type === 'JWS') {
            if (count($tokenData) !== 3) {
                throw new InvalidFormatException();
            }
            $payloadDecoded = Base64UrlEncoder::decode($tokenData[1]);
            $signatureDecoded = Base64UrlEncoder::decode($tokenData[2]);

            $token->setPayload(JwtPayload::fromJson($payloadDecoded))
                ->setSignature($signatureDecoded);
        } elseif ($type === 'JWE') {
            if (count($tokenData) !== 5) {
                throw new InvalidFormatException();
            }
            $ivDecoded = Base64UrlEncoder::decode($tokenData[1]);
            $encryptedKeyDecoded = Base64UrlEncoder::decode($tokenData[2]);
            $encryptedPayloadDecoded = Base64UrlEncoder::decode($tokenData[3]);
            $authTagDecoded = Base64UrlEncoder::decode($tokenData[4]);

            $token->setIv($ivDecoded)
                ->setEncryptedKey($encryptedKeyDecoded)
                ->setEncryptedPayload($encryptedPayloadDecoded)
                ->setAuthTag($authTagDecoded);
        } else {
            throw new InvalidFormatException();
        }

        return $token;
    }

    /**
     * Generates a JWS (signed) token string from a JwtTokenContainer.
     *
     * @param  JwtTokenContainer $token The container holding the token's header, payload, and signature.
     * @return string The assembled JWS token string.
     */
    private function generateJwsToken(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedPayload = Base64UrlEncoder::encode($token->getPayload()->toJson());
        $encodedSignature = Base64UrlEncoder::encode($token->getSignature());
        return "$encodedHeader.$encodedPayload.$encodedSignature";
    }

    /**
     * Generates a JWE (encrypted) token string from a JwtTokenContainer.
     *
     * @param  JwtTokenContainer $token The container holding the token's header, encrypted parts, and auth tag.
     * @return string The assembled JWE token string.
     */
    private function generateJweToken(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedIv = Base64UrlEncoder::encode($token->getIv() ?? '');
        $encodedCek = Base64UrlEncoder::encode($token->getEncryptedKey() ?? $token->getCek());
        $encodedPayload = Base64UrlEncoder::encode($token->getEncryptedPayload());
        $encodedAuthTag = Base64UrlEncoder::encode($token->getAuthTag());
        return "$encodedHeader.$encodedIv.$encodedCek.$encodedPayload.$encodedAuthTag";
    }
}
