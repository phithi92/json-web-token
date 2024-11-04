<?php

/**
 * This file is part of the phithi92\JsonWebToken package.
 *
 * @package phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;

/**
 * Class EmptyValueException
 *
 * Exception thrown when a required value is empty.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class EmptyValueException extends PayloadException
{
    /**
     * EmptyValueException constructor.
     *
     * @param string $key The key associated with the empty value.
     */
    public function __construct(string $key)
    {
        parent::__construct("invalid value. empty value for $key");
    }
}
