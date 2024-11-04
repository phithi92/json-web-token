<?php

namespace Phithi92\JsonWebToken\Exception\Json;

use Phithi92\JsonWebToken\Exception\Exception;

/**
 * Description of PayloadException
 *
 * @author phillip
 */
class JsonException extends Exception
{
    //put your code here

    public function __construct(string $message, ?string $field = null, ?string $secondField = null): Exception
    {
        return parent::__construct($message, $field, $secondField);
    }
}
