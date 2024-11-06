<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class InvalidDateTime
 *
 * Exception thrown when an invalid date format is encountered in the payload.
 */
class InvalidDateTimeException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(PayloadErrorMessages::INVALID_DATETIME->getMessage($field));
    }
}
