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
 * Class InvalidIssuer
 *
 * Exception thrown when the issuer of the token is invalid.
 */
class InvalidIssuer extends PayloadException
{
    /**
     * Error message indicating an invalid issuer.
     *
     * @var string
     */
    protected $message = 'Invalid issuer';

    /**
     * InvalidIssuer constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
