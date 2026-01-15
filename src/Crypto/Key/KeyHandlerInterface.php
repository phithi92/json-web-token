<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;

interface KeyHandlerInterface
{
    public function __construct(JwtKeyManager $manager);

    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function unwrapKey(JwtBundle $bundle, array $config): void;

    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function wrapKey(JwtBundle $bundle, array $config): void;
}
