<?php

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;
use Phithi92\JsonWebToken\Exception\Payload\PayloadErrorMessages;

/**
 * Class MissingData
 *
 * Exception thrown when a required payload data field is missing.
 */
class ValueNotFoundException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(PayloadErrorMessages::VALUE_NOT_FOUND->getMessage($field));
    }
}
