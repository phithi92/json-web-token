<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

final class HandlerDescriptor
{
    public function __construct(
        public readonly HandlerType $type,
        public readonly HandlerOperation $operation,
        public readonly int $priority = 100 // default priority
    ) {
    }
}
