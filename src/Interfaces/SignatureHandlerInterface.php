<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface SignatureHandlerInterface
{
    /**
     * @param array<string, int|class-string<object>> $config
     */
    public function validateSignature(JwtBundle $bundle, array $config): void;

    /**
     * @param array<string, int|class-string<object>> $config
     */
    public function computeSignature(JwtBundle $bundle, array $config): void;
}
