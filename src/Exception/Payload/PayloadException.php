<?php

/**
 * This file is part of the phithi92/json-web-token package.
 *
 * @package phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

use Phithi92\JsonWebToken\Exception\Exception;

/**
 * Class PayloadException
 *
 * Base exception for payload-related errors in the phithi92/json-web-token package.
 */
class PayloadException extends Exception
{
    /**
     * PayloadException constructor.
     *
     * @param string $message     The error message for the exception.
     * @param string|null $field  Optional specific field related to the error.
     * @param string|null $secondField Another optional field related to the error.
     */
    public function __construct(string $message, ?string $field = null, ?string $secondField = null)
    {
        parent::__construct($message, $field, $secondField);
    }
}
