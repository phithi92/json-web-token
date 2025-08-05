<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

interface KeyHandlerInterface
{
    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function unwrapKey(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * @param array<string,string|int|class-string<object>> $config
     */
    public function wrapKey(EncryptedJwtBundle $bundle, array $config): void;
}
