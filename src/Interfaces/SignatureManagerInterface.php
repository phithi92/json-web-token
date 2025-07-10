<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\EncryptedJwtBundle;

interface SignatureManagerInterface
{
    /**
     * @param array<string, string> $config
     */
    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * @param array<string, string> $config
     */
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void;
}
