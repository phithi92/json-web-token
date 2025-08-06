<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

class UnsupportedHandlerMethodException extends HandlerException
{
    public function __construct()
    {
        parent::__construct('UNSUPPORTED_HANDLER_METHOD');
    }
}
