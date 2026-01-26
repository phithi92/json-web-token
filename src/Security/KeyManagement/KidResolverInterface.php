<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security\KeyManagement;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface KidResolverInterface
{
    /**
     * @param array<string, mixed> $config
     */
    public function resolve(JwtBundle $bundle, array $config): string;
}
