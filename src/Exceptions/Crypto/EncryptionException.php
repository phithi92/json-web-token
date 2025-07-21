<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class EncryptionException extends CryptoException
{
    public function __construct(string $errorMessage)
    {
        parent::__construct('ENCRYPTION_FAILED', $errorMessage);
    }
}
