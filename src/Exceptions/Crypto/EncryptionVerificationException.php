<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class EncryptionVerificationException extends CryptoException
{
    public function __construct(string $message)
    {
        parent::__construct('VERIFICATION_FAILED', $message);
    }
}
