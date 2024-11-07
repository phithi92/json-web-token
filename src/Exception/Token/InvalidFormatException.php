<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\Token\TokenException;
use Phithi92\JsonWebToken\Exception\Token\TokenErrorMessages;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class InvalidFormatException extends TokenException
{
    public function __construct(): Exception
    {
        parent::__construct(TokenErrorMessages::INVALID_FORMAT->getMessage());
    }
}
