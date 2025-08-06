<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

class InvalidHandlerClassDefinitionException extends HandlerException
{
    public function __construct(string $type)
    {
        parent::__construct('INVALID_HANDLER_DEFINITION', $type);
    }
}
