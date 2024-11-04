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
 * Class Expired
 *
 * Exception thrown when a token has expired.
 */
class Expired extends PayloadException
{
    /**
     * Expired constructor.
     */
    public function __construct()
    {
        parent::__construct(ExceptionEnum::INVALID_TOKEN_EXPIRED);
    }
}
