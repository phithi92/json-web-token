<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class NotYetValid
 *
 * Exception thrown when the token is not yet valid.
 */
class NotYetValidException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::FUTURE_TOKEN->getMessage());
    }
}
