<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class InvalidValue
 *
 * Exception thrown when an invalid value is encountered in the payload.
 */
class InvalidValueTypeException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::INVALID_VALUE_TYPE->getMessage());
    }
}
