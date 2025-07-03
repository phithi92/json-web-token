<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class InvalidAsymmetricKeyException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_ASYMETRIC_KEY->getMessage(openssl_error_string()));
    }
}
