<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Payload;

use Phithi92\JsonWebToken\Exceptions\Exception;

class EmptyFieldException extends Exception
{
    public function __construct(string|int $name)
    {
        parent::__construct(ErrorMessagesEnum::EMPTY_VALUE->getMessage($name));
    }
}
