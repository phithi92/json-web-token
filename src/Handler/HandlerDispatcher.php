<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use RuntimeException;

final class HandlerDispatcher
{
    public function __construct(
        private readonly HandlerMethodResolver $methodResolver,
    ) {
    }

    /**
     * Dispatches a handler method call based on type and operation.
     *
     * @param array<string,mixed> $config
     * @param array<string,mixed> $context
     */
    public function dispatch(
        HandlerType $type,
        HandlerOperation $operation,
        JwtAlgorithmManager $manager,
        array $config,
        array $context = []
    ): mixed {
        if (! $this->isHandlerConfigured($config, $type)) {
            return null;
        }

        $handler = $this->buildHandler($config, $manager, $type);
        $method = $this->resolveMethod($type, $operation);

        $this->assertValidHandlerMethod($handler, $method);

        $args = $this->resolveArguments($type, $context, $config);

        return $handler->{$method}(...$args);
    }

    private function resolveMethod(
        HandlerType $type,
        HandlerOperation $operation,
    ): string {
        return $this->methodResolver->resolve($type, $operation);
    }

    private function assertValidHandlerMethod(object $handler, string $method): void
    {
        if (! method_exists($handler, $method)) {
            throw new RuntimeException('Handler ' . $handler::class . " has no method {$method}()");
        }
    }

    /**
     * @param array<string,mixed> $config
     *
     * @throws RuntimeException
     */
    private function buildHandler(
        array $config,
        JwtAlgorithmManager $manager,
        HandlerType $type
    ): object {
        $interface = $type->interface();

        if (! isset($config[$interface]) || ! is_array($config[$interface])) {
            throw new RuntimeException('Missing handler configuration');
        }

        $class = $config[$interface]['handler'];
        if (! is_string($class)) {
            throw new RuntimeException('Handler class is no valid class string');
        }

        if (! is_subclass_of($class, $interface)) {
            throw new RuntimeException("Handler {$class} must implement {$interface}");
        }

        $handler = new $class($manager);
        if (! ($handler instanceof $interface)) {
            throw new RuntimeException("Handler {$class} must implement {$interface}");
        }

        return $handler;
    }

    /**
     * @param array<string,mixed> $config
     */
    private function isHandlerConfigured(array $config, HandlerType $type): bool
    {
        return isset($config[$type->interface()]);
    }

    /**
     * Resolves method arguments for the given handler type.
     *
     * @param array<string,mixed> $context
     * @param array<string,mixed> $config
     *
     * @return array{EncryptedJwtBundle, array<string,string>}
     */
    private function resolveArguments(HandlerType $type, array $context, array $config): array
    {
        /** @var EncryptedJwtBundle $bundle */
        $bundle = $context['bundle'];

        /** @var array<string,string> $methodConfig */
        $methodConfig = $config[$type->interface()];

        $handlerConf = [$bundle, $methodConfig];

        return match ($type) {
            HandlerType::Signature,
            HandlerType::Cek,
            HandlerType::Iv,
            HandlerType::Key,
            HandlerType::Payload => $handlerConf,
        };
    }
}
