<?php

namespace Phithi92\JsonWebToken\Exceptions;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

class InvalidTokenTypeConfigException extends TokenException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_CONFIG_TOKEN_TYPE->getMessage());
    }
}
