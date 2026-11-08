<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Decryptor;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Parser\JwtTokenParser;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

/**
 * Component class for decrypting and validating encrypted JWTs.
 *
 * This class handles the reverse lifecycle of a JWT, including:
 * - Parsing tokens into structured `JwtBundle` objects.
 * - Applying decryption and decoding logic via registered handlers.
 * - Optionally validating claims using a configurable `JwtValidator`.
 *
 * Designed for use with a `JwtKeyManager` to resolve algorithm-specific behavior
 * and with pluggable handlers for custom decryption logic or post-processing.
 */
final class JwtTokenDecryptor extends AbstractJwtTokenProcessor
{
    /**
     * Specifies that the handler chain should be executed in reverse order,
     * which is required to *decrypt* a previously encrypted JWT token.
     */
    private const OPERATION = CryptoOperationDirection::Reverse;

    private readonly JwtValidator $validator;

    /**
     * JwtTokenDecryptor constructor.
     *
     * @param JwtKeyManager $manager provides cryptographic handler configurations
     */
    public function __construct(
        JwtKeyManager $manager,
        JwtValidator $validator
    ) {
        // Initialize token decryptor with "reverse" handler operation
        parent::__construct(self::OPERATION, $manager);

        $this->validator = $validator;
    }

    /**
     * Fully decrypts and validates a JWT token.
     *
     * @param string $token the encrypted JWT string
     *
     * @return JwtBundle the fully decrypted and validated JWT payload bundle
     */
    public function decrypt(string $token): JwtBundle
    {
        $bundle = $this->decryptWithoutClaimValidation($token);

        $this->validator->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Decrypts a JWT token without running any validation checks.
     *
     * Useful for debugging or low-trust environments where validation is handled elsewhere.
     *
     * @param string $token the encrypted JWT string
     *
     * @return JwtBundle the decrypted JWT payload bundle
     */
    public function decryptWithoutClaimValidation(string $token): JwtBundle
    {
        $bundle = JwtTokenParser::parse($token);
        $algorithm = $this->resolveAlgorithm($bundle);

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }
}
