<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class NotBeforeOlderThanExp
 *
 * Exception thrown when the "not before" (nbf) timestamp is older than the expiration (exp) timestamp.
 */
class IatEarlierThanExpException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::INVALID_IAT->getMessage());
    }
}
