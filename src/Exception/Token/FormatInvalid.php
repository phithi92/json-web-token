<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\Token\TokenException;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class FormatInvalid extends TokenException
{
    //put your code here
    public function __construct(): Exception
    {
        return parent::__construct('Invalid JWT format: The provided string does not meet the expected JWT structure.');
    }
}
