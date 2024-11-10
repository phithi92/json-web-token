<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class NotBeforeOlderThanExp
 *
 * Exception thrown when the "not before" (nbf) timestamp is older than the expiration (exp) timestamp.
 */
class NotBeforeOlderThanExpException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::NBF_BEFORE_IAT->getMessage());
    }
}
