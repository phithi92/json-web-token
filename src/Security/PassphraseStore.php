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

    public function addPassphrase(#[\SensitiveParameter] string $passphrase, ?string $kid): string
    {
        $kid ??= KeyIdentifier::fromSecret($passphrase);
        return $this->phrases[$kid] = $passphrase;
    }

    public function getPassphrase(#[\SensitiveParameter] string $kid): string
    {
        if (! isset($this->phrases[$kid])) {
            throw new RuntimeException("No passphrase found for ID: {$kid}");
        }

        return $this->phrases[$kid];
    }

    public function hasPassphrase(#[\SensitiveParameter] string $kid): bool
    {
        return isset($this->phrases[$kid]);
    }
}
