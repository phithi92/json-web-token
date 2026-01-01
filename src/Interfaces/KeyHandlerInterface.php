<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface KeyHandlerInterface
{
    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function unwrapKey(JwtBundle $bundle, array $config): void;

    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function wrapKey(JwtBundle $bundle, array $config): void;
}
