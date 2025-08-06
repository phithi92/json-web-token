<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

class InvalidHandlerImplementationException extends HandlerException
{
    public function __construct(string $handler, string $method)
    {
        parent::__construct('INVALID_HANDLER_CLASS', $handler, $method);
    }
}
