<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Interfaces\PassphraseStoreInterface;
use RuntimeException;

final class PassphraseStore implements PassphraseStoreInterface
{
    /**
     * @var array<string,string> $phrases
     */
    private array $phrases = [];

    public function addPassphrase(#[\SensitiveParameter] string $passphrase, ?string $kid): void
    {
        $resolvedKid = $kid ?? KeyIdentifier::fromSecret($passphrase);
        $this->phrases[$resolvedKid] = $passphrase;
    }

    public function getPassphrase(string $kid): string
    {
        if (! isset($this->phrases[$kid])) {
            throw new RuntimeException("No passphrase found for ID: {$kid}");
        }
        return $this->phrases[$kid];
    }

    public function hasPassphrase(string $kid): bool
    {
        return isset($this->phrases[$kid]);
    }
}
