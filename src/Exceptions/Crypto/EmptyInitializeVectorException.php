<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;

class EmptyInitializeVectorException extends CryptoException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::EMPTY_IV->getMessage());
    }
}
