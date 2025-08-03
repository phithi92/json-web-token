<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;

/**
 * Component class for decrypting and validating encrypted JWTs.
 *
 * This class handles the reverse lifecycle of a JWT, including:
 * - Parsing tokens into structured `EncryptedJwtBundle` objects.
 * - Applying decryption and decoding logic via registered handlers.
 * - Optionally validating claims using a configurable `JwtValidator`.
 *
 * Designed for use with a `JwtAlgorithmManager` to resolve algorithm-specific behavior
 * and with pluggable handlers for custom decryption logic or post-processing.
 */
final class JwtTokenDecryptor extends AbstractJwtTokenProcessor
{
    /**
     * JwtTokenDecryptor constructor.
     *
     * @param JwtAlgorithmManager $manager   Provides cryptographic handler configurations.
     */
    public function __construct(
        JwtAlgorithmManager $manager,
    ) {
        // Initialize token decryptor with "reverse" handler operation
        $operation = HandlerOperation::Reverse;
        parent::__construct($operation, $manager);
    }

    /**
     * Fully decrypts and validates a JWT token.
     *
     * @param string $token The encrypted JWT string.
     *
     * @return EncryptedJwtBundle The fully decrypted and validated JWT payload bundle.
     */
    public function decrypt(string $token, ?JwtValidator $validator = null): EncryptedJwtBundle
    {
        $bundle = $this->decryptWithoutClaimValidation($token);

        $this->assertValidBundle($bundle, $validator);

        return $bundle;
    }

    /**
     * Decrypts a JWT token without running any validation checks.
     *
     * Useful for debugging or low-trust environments where validation is handled elsewhere.
     *
     * @param string $token The encrypted JWT string.
     *
     * @return EncryptedJwtBundle The decrypted JWT payload bundle.
     */
    public function decryptWithoutClaimValidation(string $token): EncryptedJwtBundle
    {
        $bundle = JwtTokenParser::parse($token);
        $algorithm = $this->resolveAlgorithm($bundle);

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }

    /**
     * Asserts that the given JWT bundle is valid.
     *
     * Uses the provided validator if given, otherwise falls back to a default JwtValidator.
     *
     * @param EncryptedJwtBundle $bundle   The token bundle to validate
     * @param JwtValidator|null $validator Optional custom validator
     *
     * @throws PayloadException If payload-related validation fails
     * @throws TokenException If token structure or format is invalid
     */
    private function assertValidBundle(EncryptedJwtBundle $bundle, ?JwtValidator $validator = null): void
    {
        $validator ??= new JwtValidator();
        $validator->assertValidBundle($bundle);
    }
}
