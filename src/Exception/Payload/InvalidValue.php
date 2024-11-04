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
 * Class InvalidValue
 *
 * Exception thrown when an invalid value is encountered in the payload.
 */
class InvalidValue extends Exception
{
    /**
     * Error message indicating a key conflict.
     *
     * @var string
     */
    protected $message = ExceptionEnum::KEY_ALREADY_EXIST;

    /**
     * InvalidValue constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
