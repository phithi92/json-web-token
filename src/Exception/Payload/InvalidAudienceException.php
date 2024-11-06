<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

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
        parent::__construct(PayloadErrorMessages::INVALID_AUDIENCE->getMessage());
    }
}
