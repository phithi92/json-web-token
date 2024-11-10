<?php

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\ErrorMessagesEnum;

/**
 * Class MissingData
 *
 * Exception thrown when a required payload data field is missing.
 */
class ValueNotFoundException extends PayloadException
{
    public function __construct(string $field)
    {
        parent::__construct(ErrorMessagesEnum::VALUE_NOT_FOUND->getMessage($field));
    }
}
