<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class InvalidIssuer
 *
 * Exception thrown when the issuer of the token is invalid.
 */
class InvalidIssuedAtException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::EXPIRED_PAYLOAD->getMessage());
    }
}
