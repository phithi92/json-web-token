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
 * Class DataNotUnique
 *
 * Exception thrown when a payload data key is not unique.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class DataNotUnique extends PayloadException
{
    /**
     * DataNotUnique constructor.
     *
     * @param string $field The name of the field that is not unique.
     */
    public function __construct(string $field)
    {
        parent::__construct(ExceptionEnum::KEY_ALREADY_EXIST, $field);
    }
}
