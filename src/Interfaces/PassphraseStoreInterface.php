<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

interface PassphraseStoreInterface
{
    public function addPassphrase(string $passphrase, ?string $id): void;

    public function getPassphrase(string $id): string;

    public function hasPassphrase(string $id): bool;
}
