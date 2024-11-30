<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Exception;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class EmptyFieldException
 *
 * Exception thrown when a required value is empty.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EmptyFieldException extends Exception
{
    public function __construct(string|int $name)
    {
        parent::__construct(ErrorMessagesEnum::EMPTY_VALUE->getMessage($name));
    }
}
