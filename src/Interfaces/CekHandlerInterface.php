<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface CekHandlerInterface
{
    /**
     * Generates or loads the Content Encryption Key (CEK)
     * and attaches it to the bundle.
     *
     * @param array<string,string|int|class-string<object>> $config
     *                                                              Configuration array (expects 'length' in bits)
     */
    public function initializeCek(JwtBundle $bundle, array $config): void;

    /**
     * Validates the CEK against expected configuration (length, format, etc).
     *
     * @param array<string,string|int|class-string<object>> $config
     *                                                              Configuration array (expects 'length' in bits)
     */
    public function validateCek(JwtBundle $bundle, array $config): void;
}
