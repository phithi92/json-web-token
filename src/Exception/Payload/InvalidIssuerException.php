<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class InvalidIssuer
 *
 * Exception thrown when the issuer of the token is invalid.
 */
class InvalidIssuerException extends PayloadException
{
    public function __construct()
    {
        parent::__construct(PayloadErrorMessages::INVALID_ISSUER->getMessage());
    }
}
