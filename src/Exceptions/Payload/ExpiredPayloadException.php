<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class Expired
 *
 * Exception thrown when a token has expired.
 */
class ExpiredPayloadException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::PAYLOAD_EXPIRED->getMessage());
    }
}
