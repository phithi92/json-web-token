<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

class EncryptionVerificationException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::VERIFICATION_FAILED->getMessage(openssl_error_string()));
    }
}
