<?php

/**
 * This file is part of the JsonWebToken package.
 *
 * @package Phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Payload\PayloadException;

/**
 * Class NotYetValid
 *
 * Exception thrown when the token is not yet valid.
 */
class NotYetValid extends PayloadException
{
    /**
     * Error message indicating that the token is not yet valid.
     *
     * @var string
     */
    protected $message = ExceptionEnum::TOKEN_NOT_YET_VALID;

    /**
     * NotYetValid constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
