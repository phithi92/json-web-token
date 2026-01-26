<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Exceptions\Security\PassphraseNotFoundException;
use SensitiveParameter;

final class PassphraseStore
{
    /**
     * @var array<string, string> Map of key ID to passphrase
     */
    private array $phrases = [];

    /**
     * Adds a passphrase and returns the resolved key ID.
     *
     * @param string    $passphrase The secret passphrase
     * @param string    $kid        Optional key ID. If null, it will be derived from the passphrase
     *
     * @return string The resolved key ID
     */
    public function addPassphrase(#[SensitiveParameter] string $passphrase, string $kid): string
    {
        $this->phrases[$kid] = $passphrase;

        return $kid;
    }

    /**
     * Retrieves a passphrase by key ID.
     *
     * @param string $kid The key ID
     *
     * @throws PassphraseNotFoundException If no passphrase is found for the given key ID
     */
    public function getPassphrase(#[SensitiveParameter] string $kid): string
    {
        return $this->phrases[$kid]
            ?? throw new PassphraseNotFoundException($kid);
    }

    /**
     * Checks whether a passphrase exists for the given key ID.
     *
     * @param string $kid The key ID
     */
    public function hasPassphrase(#[SensitiveParameter] string $kid): bool
    {
        return isset($this->phrases[$kid]);
    }
}
