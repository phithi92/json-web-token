<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class NotYetValid
 *
 * Exception thrown when the token is not yet valid.
 */
class NotYetValidException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::FUTURE_TOKEN->getMessage());
    }
}
