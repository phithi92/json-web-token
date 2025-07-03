<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class InvalidSecretLengthException extends CryptoException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_SECRET_LENGTH->getMessage($length, $expect));
    }
}
