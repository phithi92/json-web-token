<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class InvalidInitializationVectorConfigException extends CryptoException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_CONFIG->getMessage($length, $expect));
    }
}
