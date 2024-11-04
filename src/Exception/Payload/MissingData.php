<?php

/**
 * This file is part of the JsonWebToken package.
 *
 * @package Phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\ExceptionEnum;
use Phithi92\JsonWebToken\Exception\Exception;

/**
 * Class MissingData
 *
 * Exception thrown when a required payload data field is missing.
 */
class MissingData extends Exception
{
    /**
     * MissingData constructor.
     *
     * @param string $field The name of the missing field in the payload.
     */
    public function __construct(string $field)
    {
        parent::__construct(ExceptionEnum::MISSING_PAYLOAD_DATA, $field);
    }
}
