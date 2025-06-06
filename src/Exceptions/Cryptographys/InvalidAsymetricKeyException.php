<?php

namespace Phithi92\JsonWebToken\Exceptions\Cryptographys;

use Phithi92\JsonWebToken\Exceptions\Cryptographys\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\CryptographyException;

class InvalidAsymetricKeyException extends CryptographyException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_ASYMETRIC_KEY->getMessage(openssl_error_string()));
    }
}
