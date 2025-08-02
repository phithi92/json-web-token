<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Handler\HandlerOperation;

interface JwtTokenOperation
{
    public function getOperation(): HandlerOperation;
}
