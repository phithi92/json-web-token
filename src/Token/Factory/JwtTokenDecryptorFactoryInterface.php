<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

interface JwtTokenDecryptorFactoryInterface
{
    public function createDecryptor(JwtKeyManager $manager): JwtTokenDecryptor;
}
