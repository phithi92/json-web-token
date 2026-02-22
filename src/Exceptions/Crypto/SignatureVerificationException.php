<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class SignatureVerificationException extends CryptoException
{
    public function __construct(string $message)
    {
        parent::__construct('SIGNATURE_VERIFICATION_FAILED', $message);
    }
}
