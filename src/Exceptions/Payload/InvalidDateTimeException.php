<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class InvalidDateTime
 *
 * Exception thrown when an invalid date format is encountered in the payload.
 */
class InvalidDateTimeException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::INVALID_DATETIME->getMessage($field));
    }
}
