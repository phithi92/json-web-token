<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class Expired
 *
 * Exception thrown when a token has expired.
 */
class ExpiredPayloadException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::PAYLOAD_EXPIRED->getMessage());
    }
}
