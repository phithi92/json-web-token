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
        $handlerClass = self::resolveHandlerClass($config, $key);

        /** @var T $handler */
        $handler = new $handlerClass(...$constructorArgs);

        self::assertImplementsInterface($handler, $interface, $key);

        return $handler;
    }

    /**
     *
     * @param array<string,mixed> $config The algorithm config array.
     * @param string $key
     * @return string
     * @throws LogicException
     */
    private static function resolveHandlerClass(array $config, string $key): string
    {
        $entry = $config[$key] ?? null;

        if (!is_array($entry)) {
            throw new LogicException("Missing config entry for key '{$key}'.");
        }

        if (!isset($entry['handler']) || !is_string($entry['handler'])) {
            throw new LogicException("Invalid or missing 'handler' for key '{$key}'.");
        }

        if (!class_exists($entry['handler'])) {
            throw new LogicException("Handler class '{$entry['handler']}' does not exist.");
        }

        return $entry['handler'];
    }

    private static function assertImplementsInterface(object $handler, string $interface, string $key): void
    {
        if (!$handler instanceof $interface) {
            throw new LogicException(
                sprintf(
                    'Handler for "%s" must implement %s. Got %s.',
                    $key,
                    $interface,
                    get_debug_type($handler)
                )
            );
        }
    }
}
