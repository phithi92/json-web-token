<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

class InvalidKidLengthException extends TokenException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_KID_LENGTH->getMessage($length, $expect));
    }
}
