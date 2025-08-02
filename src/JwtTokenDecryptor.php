<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\Processor\AbstractJwtTokenProcessor;

final class JwtTokenDecryptor extends AbstractJwtTokenProcessor
{
    public const OPERATION = HandlerOperation::Reverse;

    /**
     * @var JwtValidator Validates the integrity and structure of the decrypted JWT bundle.
     */
    private readonly JwtValidator $validator;

    /**
     * JwtTokenDecryptor constructor.
     *
     * @param JwtAlgorithmManager $manager   Provides cryptographic handler configurations.
     * @param JwtValidator|null   $validator Optional validator; defaults to JwtValidator if not provided.
     */
    public function __construct(
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator = null
    ) {
        parent::__construct($manager);
        $this->validator = ($validator ?? new JwtValidator());
    }

    /**
     * Fully decrypts and validates a JWT token.
     *
     * @param string $token The encrypted JWT string.
     *
     * @return EncryptedJwtBundle The fully decrypted and validated JWT payload bundle.
     */
    public function decrypt(string $token): EncryptedJwtBundle
    {
        $bundle = $this->decryptWithoutValidation($token);
        $this->validator->assertValidBundle($bundle);
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
    public function decryptWithoutValidation(string $token): EncryptedJwtBundle
    {
        $bundle = JwtTokenParser::parse($token);

        $algorithm = $this->resolveAlgorithm($bundle);

        $this->dispatchHandlers($bundle, $algorithm);

        return $bundle;
    }
}
