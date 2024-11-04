<?php

namespace Phithi92\JsonWebToken\Exception\Token;

use Phithi92\JsonWebToken\Exception\Token\TokenException;

/**
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class SignatureInvalid extends TokenException
{
    //put your code here
    public function __construct(): Exception
    {
        return parent::__construct('Signature verification failed: The JWT signature is invalid or has been altered.');
    }
}
