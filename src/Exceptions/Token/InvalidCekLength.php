<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

class InvalidCekLength extends TokenException
{
    public function __construct(int $length, int $expect)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_CEK_LENGTH->getMessage($length, $expect));
    }
}
