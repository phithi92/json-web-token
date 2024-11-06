<?php

namespace Phithi92\JsonWebToken\Exception;

use Phithi92\JsonWebToken\Exception\ErrorMessages;
use Phithi92\JsonWebToken\Exception\EmptyFieldException;
use Exception;

/**
 * Class EmptyValueException
 *
 * Exception thrown when a required value is empty.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EmptyFieldException extends Exception
{
    public function __construct(string $name)
    {
        parent::__construct(ErrorMessages::EMPTY_VALUE->getMessage($name));
    }
}
