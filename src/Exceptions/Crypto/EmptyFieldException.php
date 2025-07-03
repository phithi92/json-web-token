<?php

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\ErrorMessagesEnum;

class EmptyFieldException extends CryptoException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::EMPTY_FIELD->getMessage($field));
    }
}
