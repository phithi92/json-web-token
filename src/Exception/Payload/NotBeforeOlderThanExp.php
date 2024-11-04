<?php

/**
 * This file is part of the phithi92\JsonWebToken package.
 *
 * @package phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\ExceptionEnum;
use Phithi92\JsonWebToken\Exception\Exception;

/**
 * Class NotBeforeOlderThanExp
 *
 * Exception thrown when the "not before" (nbf) timestamp is older than the expiration (exp) timestamp.
 */
class NotBeforeOlderThanExp extends Exception
{
    /**
     * Error message indicating that "not before" is earlier than "expiration".
     *
     * @var string
     */
    protected $message = ExceptionEnum::INVALID_TOKEN_NBF_TO_EARLY;

    /**
     * NotBeforeOlderThanExp constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
