<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Reader;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactoryInterface;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtTokenReader
{
    public function __construct(
        private readonly JwtTokenDecryptorFactoryInterface $decryptorFactory,
    ) {
    }

    public function decryptToken(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $decryptor = $this->decryptorFactory->createDecryptor($manager);

        return $decryptor->decrypt(token: $token, validator: $validator);
    }

    public function decryptTokenWithoutClaimValidation(
        string $token,
        JwtKeyManager $manager,
    ): JwtBundle {
        $decryptor = $this->decryptorFactory->createDecryptor($manager);

        return $decryptor->decryptWithoutClaimValidation(token: $token);
    }
}
