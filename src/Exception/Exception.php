<?php

namespace Phithi92\JsonWebToken\Exception;

use Exception as PlatformException;

class Exception extends PlatformException
{
    public function __construct(string $message, ?string $field = null, ?string $secondField = null)
    {
        if ($field && $secondField) {
            $message = sprintf($message, $field, $secondField);
        } elseif ($field) {
            $message = sprintf($message, $field);
        }

        parent::__construct($message);
    }
}
