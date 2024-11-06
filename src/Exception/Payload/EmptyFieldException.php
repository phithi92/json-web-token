<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Exception;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class EmptyFieldException
 *
 * Exception thrown when a required value is empty.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EmptyFieldException extends Exception
{
    public function __construct(string $name)
    {
        parent::__construct(PayloadErrorMessages::EMPTY_VALUE->getMessage($name));
    }
}
