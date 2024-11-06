<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class NotBeforeOlderThanIat
 *
 * Exception thrown when the "not before" (nbf) timestamp is older than the "issued at" (iat) timestamp.
 */
class NotBeforeOlderThanIatException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::NBF_BEFORE_IAT->getMessage());
    }
}
