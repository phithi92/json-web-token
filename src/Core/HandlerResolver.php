<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Core;

use LogicException;

final class HandlerResolver
{
    /**
     * Instantiates and validates a handler based on config and interface.
     *
     * @template T of object
     *
     * @param array<string,mixed> $config             The algorithm config array.
     * @param string              $key                The config key (e.g. 'cek', 'key_management', etc.)
     * @param class-string<T>     $interface          The expected interface the handler must implement.
     * @param mixed               ...$constructorArgs Arguments to pass to the constructor.
     *
     * @return T An instance of the handler implementing the expected interface.
     */
    public static function resolve(array $config, string $key, string $interface, mixed ...$constructorArgs): mixed
    {
        $handlerClass = $config[$key]['handler'] ?? null;

        if (! is_string($handlerClass) || ! class_exists($handlerClass)) {
            throw new LogicException(sprintf('Invalid or missing handler for "%s" (%s).', $key, $interface));
        }

        $handler = new $handlerClass(...$constructorArgs);

        if (! $handler instanceof $interface) {
            throw new LogicException(
                sprintf(
                    'Handler for "%s" must implement %s. Got %s.',
                    $key,
                    $interface,
                    get_debug_type($handler)
                )
            );
        }

        return $handler;
    }
}
