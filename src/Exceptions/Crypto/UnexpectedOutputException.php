<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;

class UnexpectedOutputException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::UNEXPECTED_OUTPUT->getMessage());
    }
}
