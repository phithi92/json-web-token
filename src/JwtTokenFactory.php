<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidJti;
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
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
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
    public function __construct(JwtAlgorithmManager|null $manager)
    {
        $this->manager = $manager;
        $algorithm = $this->getManager()->getAlgorithm();

        $processor = $this->createProcessorForAlgorithm($algorithm);
        if ($processor === null) {
            throw new UnsupportedAlgorithmException($algorithm);
        }
        $this->processor = $processor;

        $this->getManager()->setTokenType($processor->getTokenType());
    }

    /**
     * Creates a JSON Web Token (JWT) using the provided payload.
     *
     * Determines if the token should be a JWS (signed) or JWE (encrypted),
     * and constructs the token accordingly. The token's usage is defined
     *
     * @param  JwtPayload $payload The data to encode within the JWT payload.
     * @param  JwtPayload $payload  The data to encode within the JWT payload.
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
        // Parse the encrypted token to obtain the decoded token data
        $decodedToken = $this->getProcessor()->parse($encryptedToken);

        // Decrypt the parsed token to retrieve the original token data
        $token = $this->getProcessor()->decrypt($decodedToken);

        // Verify the decrypted token to ensure its validity and integrity
        $this->getProcessor()->verify($token);

        return $token;
    }




    /**
     * Static method to refresh an existing JWT token with a new expiration interval.
     *
     * This method creates a new instance of the class using the specified
     * JWT algorithm manager and calls the instance method `refresh`.
     * It returns a refreshed JWT with an updated expiration interval.
     *
     * @param  JwtAlgorithmManager $algorithm          The algorithm manager for handling token operations.
     * @param  string              $encryptedToken     The existing encoded JWT token to be refreshed.
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
     * Creates and returns the appropriate processor instance based on the specified algorithm.
     *
     * Checks if the given algorithm is supported by either the SignatureProcessor or EncodingProcessor.
     * If supported, it initializes and returns the corresponding processor with the current manager.
     * Returns null if the algorithm is unsupported, indicating no suitable processor is available.
     *
     * @param  string $algorithm The algorithm for which a processor is needed.
     * @return Processor|null An instance of the appropriate processor, or null if unsupported.
     */
    private function createProcessorForAlgorithm(string $algorithm): Processor|null
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
}
