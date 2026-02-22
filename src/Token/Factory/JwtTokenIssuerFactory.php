<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;

final class JwtTokenIssuerFactory implements JwtTokenIssuerFactoryInterface
{
    public function createIssuer(JwtKeyManager $manager): JwtTokenIssuer
    {
        return new JwtTokenIssuer($manager);
    }
}
