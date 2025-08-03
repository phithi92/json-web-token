<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

interface CekHandlerInterface
{
    /**
     * Generates or loads the Content Encryption Key (CEK)
     * and attaches it to the bundle.
     *
     * @param array<string, int|string> $config
     *          Configuration array (expects 'length' in bits).
     */
    public function initializeCek(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * Validates the CEK against expected configuration (length, format, etc).
     *
     * @param array<string, int|string> $config
     *          Configuration array (expects 'length' in bits).
     */
    public function validateCek(EncryptedJwtBundle $bundle, array $config): void;
}
