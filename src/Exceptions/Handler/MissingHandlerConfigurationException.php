<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Handler;

class MissingHandlerConfigurationException extends HandlerException
{
    public function __construct()
    {
        parent::__construct('MISSING_HANDLER_CONFIG');
    }
}
