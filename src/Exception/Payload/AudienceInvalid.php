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
 * Class AudienceInvalid
 *
 * Exception thrown when the audience of the token is not valid.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class AudienceInvalid extends PayloadException
{
    /**
     * Error message indicating that the audience is not valid.
     *
     * @var string
     */
    protected $message = 'Audience is not valid';

    /**
     * AudienceInvalid constructor.
     */
    public function __construct()
    {
        parent::__construct($this->message);
    }
}
