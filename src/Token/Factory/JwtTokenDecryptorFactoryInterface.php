<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Decryptor\JwtTokenDecryptor;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

interface JwtTokenDecryptorFactoryInterface
{
    public function createDecryptor(JwtKeyManager $manager, JwtValidator $validator): JwtTokenDecryptor;
}
