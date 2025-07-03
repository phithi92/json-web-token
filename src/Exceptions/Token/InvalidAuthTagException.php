<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

class InvalidAuthTagException extends TokenException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_AUTH_TAG->getMessage());
    }
}
