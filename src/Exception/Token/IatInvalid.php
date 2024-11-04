<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\Payload\ExceptionEnum;
use Phithi92\JsonWebToken\Exception\Token\TokenException;

class IatInvalid extends TokenException
{
    public function __construct()
    {
        parent::__construct(ExceptionEnum::TOKEN_IAT_IN_FUTURE);
    }
}
