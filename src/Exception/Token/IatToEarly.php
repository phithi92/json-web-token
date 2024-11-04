<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\Payload\ExceptionEnum;
use Phithi92\JsonWebToken\Exception\Token\TokenException;

class IatToEarly extends TokenException
{
    public function __construct()
    {
        parent::__construct(ExceptionEnum::INVALID_TOKEN_IAT_TO_EARLY);
    }
}
