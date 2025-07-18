<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\EncryptedJwtBundle;

interface KeyHandlerInterface
{
    /**
     * @param array<string, array<string, string|class-string<object>>|string> $config
     */
    public function unwrapKey(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * @param array<string, array<string, string|class-string<object>>|string> $config
     */
    public function wrapKey(EncryptedJwtBundle $bundle, array $config): void;
}
