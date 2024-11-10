<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class AudienceInvalid
 *
 * Exception thrown when the audience of the token is not valid.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class InvalidAudienceException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(ErrorMessagesEnum::INVALID_AUDIENCE->getMessage());
    }
}
