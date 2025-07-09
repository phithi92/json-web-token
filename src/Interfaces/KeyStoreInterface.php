<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use OpenSSLAsymmetricKey;

interface KeyStoreInterface
{
    public function addKey(#[\SensitiveParameter] string $pem, ?string $role = null, ?string $kid = null): string;

    public function getKey(string $kid, string $role): OpenSSLAsymmetricKey;

    public function hasKey(string $kid, string $role): bool;
}
