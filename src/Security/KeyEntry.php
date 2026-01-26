<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;

final class KeyEntry
{
    private readonly OpenSSLAsymmetricKey $key;
    private readonly KeyRole $role;
    private readonly KeyType $type;
    private readonly int $bits;
    private readonly string $pem; // wenn überhaupt nötig

    public function __construct(
        OpenSSLAsymmetricKey $key,
        KeyRole $role,
        KeyType $type,
        string $pem, // wenn überhaupt nötig
        ?int $bits = null,
    ) {
        $this->key = $key;
        $this->role = $role;
        $this->type = $type;
        $this->bits = $bits;
        $this->pem = $pem;
    }

    // Verhindert versehentliches Leaken in var_dump()/dd()/Debugger

    public function __debugInfo(): array
    {
        return [
            'role' => $this->role->value,
            'type' => $this->type,
            'bits' => $this->bits,
            'key' => '(OpenSSLAsymmetricKey)',
        ];
    }

    public function key(): OpenSSLAsymmetricKey
    {
        return $this->key;
    }
    public function role(): KeyRole
    {
        return $this->role;
    }
    public function type(): KeyType
    {
        return $this->type;
    }
    public function bits(): int
    {
        return $this->bits;
    }
    public function pem(): string
    {
        return $this->pem;
    }
}
