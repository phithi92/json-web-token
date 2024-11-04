<?php

/**
 * This file is part of the phithi92\JsonWebToken package.
 *
 * @package phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\ExceptionEnum;
use Phithi92\JsonWebToken\Exception\Payload\PayloadException;

/**
 * Class InvalidDateTime
 *
 * Exception thrown when an invalid date format is encountered in the payload.
 */
class InvalidDateTime extends PayloadException
{
    /**
     * InvalidDateTime constructor.
     *
     * @param string $field The name of the field with the invalid date format.
     */
    public function __construct(string $field)
    {
        parent::__construct(ExceptionEnum::ERROR_DATE_FORMAT, $field);
    }
}
