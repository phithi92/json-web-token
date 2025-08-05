<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

final class HandlerInvoker
{
    /**
     * Führt eine Methode performant auf einem Handler aus.
     *
     * @param object $handler
     * @param list<mixed> $args
     */
    public function invoke(object $handler, string $method, mixed $args): mixed
    {
        // @phpstan-ignore-next-line
        return $handler->{$method}(...$args);
    }
}
