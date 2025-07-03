<?php

namespace Phithi92\JsonWebToken\Exceptions\Token;

use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\ErrorMessagesEnum;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class InvalidSignatureException extends TokenException
{
    public function __construct(string $message)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_SIGNATURE->getMessage($message));
    }
}
