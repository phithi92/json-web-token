<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\EncryptedJwtBundle;

interface KeyManagementManagerInterface
{
    /**
     *
     * @param   EncryptedJwtBundle $bundle
     * @param   array<string, array<string, string|class-string<object>>|string> $config
     * @return  void
     */
    public function unwrapKey(EncryptedJwtBundle $bundle, array $config): void;

    /**
     *
     * @param   EncryptedJwtBundle $bundle
     * @param   array<string, array<string, string|class-string<object>>|string> $config
     * @return  void
     */
    public function wrapKey(EncryptedJwtBundle $bundle, array $config): void;
}
