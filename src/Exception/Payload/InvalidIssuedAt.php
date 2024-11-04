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
 * Class InvalidIssuedAt
 *
 * Exception thrown when the "issued at" (iat) field in the token is invalid.
 */
class InvalidIssuedAt extends PayloadException
{
    /**
     * Error message indicating an invalid "issued at" field.
     *
     * @var string
     */
    protected $message = 'Invalid issued at';

    /**
     * InvalidIssuedAt constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
