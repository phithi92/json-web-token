<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;

final class JwtTokenDecryptorFactory implements JwtTokenDecryptorFactoryInterface
{
    public function createDecryptor(JwtKeyManager $manager): JwtTokenDecryptor
    {
        return new JwtTokenDecryptor(manager: $manager);
    }
}
