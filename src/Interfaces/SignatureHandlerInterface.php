<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

interface SignatureHandlerInterface
{
    /**
     * @param array<string, int|class-string<object>> $config
     */
    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * @param array<string, int|class-string<object>> $config
     */
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void;
}
