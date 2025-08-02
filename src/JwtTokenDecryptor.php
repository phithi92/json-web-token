<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\Processor\AbstractJwtTokenProcessor;

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

        $this->dispatchHandlers($bundle, $algorithm);

        return $bundle;
    }

    private function assertValidBundle(EncryptedJwtBundle $bundle, ?JwtValidator $validator = null): void
    {
        $validator ??= new JwtValidator();
        $validator->assertValidBundle($bundle);
    }
}
