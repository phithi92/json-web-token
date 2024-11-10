<?php

namespace Phithi92\JsonWebToken\Exceptions\Cryptographys;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\CryptographyException;

class EncryptionVerificationException extends CryptographyException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::VERIFICATION_FAILED->getMessage(openssl_error_string()));
    }
}
