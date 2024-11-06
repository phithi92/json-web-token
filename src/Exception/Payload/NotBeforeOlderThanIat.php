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
 * Class NotBeforeOlderThanIat
 *
 * Exception thrown when the "not before" (nbf) timestamp is older than the "issued at" (iat) timestamp.
 */
class NotBeforeOlderThanIat extends PayloadException
{
    /**
     * Error message indicating that "not before" is earlier than "issued at".
     *
     * @var string
     */
    protected $message = ExceptionEnum::INVALID_TOKEN_NBF_EARLY_IAT;

    /**
     * NotBeforeOlderThanIat constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
