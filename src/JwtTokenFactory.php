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
 * @package Phithi92\JsonWebToken
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

    /**
     * Constructor for initializing with a JwtAlgorithmManager.
     *
     * This constructor accepts a JwtAlgorithmManager, sets it using the
     * `setManager` method, and then initializes the processor based on the
     * algorithm supported by the manager.
     *
     * @param JwtAlgorithmManager $manager The JwtAlgorithmManager to initialize the object with.
     */
    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->setManager($manager);
        $this->configureProcessorForAlgorithm();
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
        $header = new JwtHeader(
            $this->getManager()->getAlgorithm(),
            $this->getManager()->getTokenType()
        );

        $token = (new JwtTokenContainer($payload))
            ->setHeader($header);

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
                ->setIssuedAt('now')
                ->setExpiration($expirationInterval);

        return $this->create($token->getPayload());
    }

    /**
     * Static method to refresh an existing JWT token with a new expiration interval.
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
     * Static factory method to directly generate a JWT using a specified algorithm.
     *
     * This shortcut method allows creating a JWT without the need to instantiate
     * the class directly. It initializes an instance with the specified
     * algorithm manager and uses it to create the token.
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
     * Static factory method to directly decrypt a JWT using a specified algorithm.
     *
     * This shortcut method allows decrypting a JWT without instantiating the class
     * directly. It initializes an instance with the specified algorithm manager
     * and uses it to decrypt the token.
     *
     * @param  JwtAlgorithmManager $algorithm      The algorithm manager for handling token operations.
     * @param  string              $encryptedToken The encoded token string.
     * @return JwtTokenContainer The decrypted token container object.
     */
    public static function decryptToken(JwtAlgorithmManager $algorithm, string $encryptedToken): JwtTokenContainer
    {
        return (new self($algorithm))->decrypt($encryptedToken);
    }

    /**
     * Configures the token processor based on the algorithm and sets the token type accordingly.
     *
     * Checks if the current algorithm supports either JWS (JSON Web Signature) or JWE (JSON Web Encryption)
     * and sets the token type based on the appropriate processor. Throws an exception if the algorithm
     * is unsupported.
     *
     * @throws UnsupportedAlgorithmException If the algorithm is not supported.
     */
    private function configureProcessorForAlgorithm(): void
    {
        $algorithm = $this->getManager()->getAlgorithm();

        $processor = $this->createProcessorForAlgorithm($algorithm);

        if ($processor === null) {
            throw new UnsupportedAlgorithmException($algorithm);
        }

        $this->getManager()->setTokenType($processor->getTokenType());
        $this->setProcessor($processor);
    }

    /**
     * Creates and returns the appropriate processor instance based on the specified algorithm.
     *
     * Checks if the given algorithm is supported by either the SignatureProcessor or EncodingProcessor.
     * If supported, it initializes and returns the corresponding processor with the current manager.
     * Returns null if the algorithm is unsupported, indicating no suitable processor is available.
     *
     * @param string $algorithm The algorithm for which a processor is needed.
     * @return ProcessorInterface|null An instance of the appropriate processor, or null if unsupported.
     */
    private function createProcessorForAlgorithm(string $algorithm): ?Processor
    {
        if (SignatureProcessor::isSupported($algorithm)) {
            return new SignatureProcessor($this->getManager());
        }

        if (EncodingProcessor::isSupported($algorithm)) {
            return new EncodingProcessor($this->getManager());
        }

        return null; // Falls kein unterstützter Prozessor gefunden wird
    }

    /**
     * Sets the token type for the current instance.
     *
     * @param string $type The token type to set.
     * @return self Returns the current instance for chaining.
     */
    public function setTokenType(string $type): self
    {
        $this->type = $type;
        return $this;
    }

    /**
     * Retrieves the type of token (either 'JWS' or 'JWE').
     *
     * @return string The token type.
     */
    private function getTokenType(): ?string
    {
        return $this->type ?? null;
    }

    /**
     * Returns the JwtAlgorithmManager.
     *
     * @return JwtAlgorithmManager The manager for JWT algorithms.
     */
    private function getManager(): JwtAlgorithmManager
    {
        return $this->manager;
    }

    /**
     * Returns the Processor.
     *
     * This method returns the current processor responsible for processing JWTs.
     *
     * @return Processor The processor for JWT processing.
     */
    private function getProcessor(): Processor
    {
        return $this->processor;
    }

    /**
     * Sets the processor instance.
     *
     * @param Processor $processor The processor to set.
     * @return self Returns the current instance for method chaining.
     */
    private function setProcessor(Processor $processor): self
    {
        $this->processor = $processor;
        return $this;
    }

    /**
     * Sets the JwtAlgorithmManager.
     *
     * This method sets the manager responsible for handling JWT algorithms.
     *
     * @param JwtAlgorithmManager $manager The manager to set.
     * @return self The current instance for method chaining.
     */
    private function setManager(JwtAlgorithmManager $manager): self
    {
        $this->manager = $manager;
        return $this;
    }
}
