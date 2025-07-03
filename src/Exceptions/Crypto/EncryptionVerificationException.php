<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class EncryptionVerificationException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::VERIFICATION_FAILED->getMessage(openssl_error_string()));
    }
}
