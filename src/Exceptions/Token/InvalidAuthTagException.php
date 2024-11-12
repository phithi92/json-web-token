<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class InvalidAuthTagException extends TokenException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_AUTH_TAG->getMessage());
    }
}
