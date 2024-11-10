<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class InvalidFormatException extends TokenException
{
    public function __construct(): Exception
    {
        parent::__construct(ErrorMessagesEnum::INVALID_FORMAT->getMessage());
    }
}
