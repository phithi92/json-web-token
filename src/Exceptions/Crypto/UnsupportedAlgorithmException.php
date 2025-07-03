<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;

class UnsupportedAlgorithmException extends CryptoException
{
    public function __construct(string $algorithm)
    {
        parent::__construct(ErrorMessagesEnum::UNSUPPORTED->getMessage($algorithm));
    }
}
