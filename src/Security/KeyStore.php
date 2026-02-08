<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Security\OpenSsl\KeyEntryFactory;
use RuntimeException;
use SensitiveParameter;

final class KeyStore
{
    /**
     * @var array<string, array<string, KeyEntry>>
     */
    private array $keys = [];

    public function __construct(
        private readonly KeyEntryFactory $factory = new KeyEntryFactory(),
    ) {
    }

    public function addKey(
        #[SensitiveParameter]
        string $pem,
        KeyRole $role,
        string $kid,
    ): KeyEntry {
        $entry = $this->factory->build($pem, $role);
        $this->keys[$kid][$entry->role()->value] = $entry;

        return $entry;
    }

    public function getKey(string $kid, KeyRole $role): OpenSSLAsymmetricKey
    {
        return $this->getMetadata($kid, $role)->key();
    }

    public function getType(string $kid, KeyRole $role): KeyType
    {
        return $this->getMetadata($kid, $role)->type();
    }

    public function getMetadata(string $kid, KeyRole $role): KeyEntry
    {
        if (! isset($this->keys[$kid])) {
            throw new RuntimeException("Key with ID [{$kid}] not found.");
        }

        if (! isset($this->keys[$kid][$role->value])) {
            throw new RuntimeException("Role [{$role->value}] not found for key ID [{$kid}].");
        }

        return $this->keys[$kid][$role->value];
    }

    public function hasKey(string $kid, ?KeyRole $role = null): bool
    {
        return $role === null
            ? isset($this->keys[$kid])
            : isset($this->keys[$kid][$role->value]);
    }
}
