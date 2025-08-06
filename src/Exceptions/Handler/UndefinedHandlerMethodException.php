<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

class UndefinedHandlerMethodException extends HandlerException
{
    public function __construct(string $class, string $method)
    {
        parent::__construct('INVALID_IAT', $class, $method);
    }
}
