<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Processors\SignatureProcessor;
use Phithi92\JsonWebToken\Processors\EncodingProcessor;
use Phithi92\JsonWebToken\Processors\Processor;

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
    // JwtAlgorithmManager $cipher The algorithm manager for token encryption/decryption.
    private readonly JwtAlgorithmManager $manager;

    // The processor responsible for handling token creation, signing, or encryption
    // based on the token type
    private readonly Processor $processor;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->setManager($manager);
        $this->initializeProcessor();
    }

    private function initializeProcessor(): void
    {
        if (SignatureProcessor::isSupported($this->getManager()->getAlgorithm())) {
            $this->setProcessor(new SignatureProcessor($this->getManager()));
        } elseif (EncodingProcessor::isSupported($this->getManager()->getAlgorithm())) {
            $this->setProcessor(new EncodingProcessor($this->getManager()));
        } else {
            throw new UnsupportedAlgorithmException($this->getManager()->getAlgorithm());
        }
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
        $token->setHeader(new JwtHeader(
            $this->getManager()->getAlgorithm(),
            $this->getManager()->getTokenType()
        ));

        $encryptedToken = $this->getProcessor()->encrypt($token);

        return $this->getProcessor()->assemble($encryptedToken);
    }

    /**
     * Decrypts a JWT string into a JwtTokenContainer object.
     *
     * Decrypts and verifies the JWT based on its type (JWS or JWE),
     * throwing an exception if verification fails.
     *
     * @param  string $encryptedToken The encoded JWT string to decrypt.
     * @return JwtTokenContainer The decrypted token container object.
     */
    public function decrypt(string $encryptedToken): JwtTokenContainer
    {
        $decodedToken = $this->getProcessor()->parse($encryptedToken);

        $token = $this->getProcessor()->decrypt($decodedToken);
        $this->getProcessor()->verify($token);

        return $token;
    }

    /**
     * Refreshes an existing JWT by updating its expiration.
     *
     * Decrypts the token, updates its issuance and expiration times,
     * then re-generates the JWT.
     *
     * @param  string $encryptedToken      The encoded JWT string to refresh.
     * @param  string $expirationInterval The interval for the new expiration time.
     * @return string The refreshed JWT string.
     */
    public function refresh(string $encryptedToken, string $expirationInterval = '+1 hour'): string
    {
        $token = $this->decrypt($encryptedToken);

        $token->getPayload()
                ->setIssuedAt($expirationInterval)
                ->setExpiration($expirationInterval);

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
     * @param  string              $encryptedToken      The existing encoded JWT token to be refreshed.
     * @param  string              $expirationInterval The new expiration interval for the refreshed token.
     * @return string                                  The refreshed JWT token with updated expiration.
     */
    public static function refreshToken(
        JwtAlgorithmManager $algorithm,
        string $encryptedToken,
        string $expirationInterval
    ): string {
        return (new self($algorithm))->refresh($encryptedToken, $expirationInterval);
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
     * @param  string              $encryptedToken   The encoded token string.
     * @return string The generated JWT string.
     */
    public static function decryptToken(JwtAlgorithmManager $algorithm, string $encryptedToken): JwtTokenContainer
    {
        return (new self($algorithm))->decrypt($encryptedToken);
    }

    private function getManager(): JwtAlgorithmManager
    {
        return $this->manager;
    }

    public function getProcessor(): Processor
    {
        return $this->processor;
    }

    /**
     * Sets the processor instance.
     *
     * @param ProcessorInterface $processor The processor to set.
     * @return self Returns the current instance for method chaining.
     */
    private function setProcessor(Processor $processor): self
    {
        $this->processor = $processor;
        return $this;
    }

    private function setManager(JwtAlgorithmManager $manager): self
    {
        $this->manager = $manager;
        return $this;
    }
}
