<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerClassDefinitionException;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerImplementationException;
use Phithi92\JsonWebToken\Exceptions\Handler\MissingHandlerConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Handler\UndefinedHandlerMethodException;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use RuntimeException;

use function gettype;
use function is_array;
use function is_string;
use function is_subclass_of;
use function method_exists;

final class HandlerDispatcher
{
    /** @var array<class-string, object> */
    private array $handlerCache = [];

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
        HandlerTarget $target,
        HandlerOperation $operation,
        JwtAlgorithmManager $manager,
        array $config,
        array $context = [],
    ): mixed {
        if (! $this->isHandlerConfigured($config, $target)) {
            return null;
        }

        $handler = $this->buildHandler($config, $manager, $target);
        $method = $this->resolveMethod($target, $operation);

        $this->assertValidHandlerMethod($handler, $method);

        $args = $this->resolveArguments($target, $context, $config);

        /** @phpstan-ignore-next-line */
        return $handler->{$method}(...$args);
    }

    private function resolveMethod(
        HandlerTarget $target,
        HandlerOperation $operation,
    ): string {
        return $this->methodResolver->resolve($target, $operation);
    }

    private function assertValidHandlerMethod(object $handler, string $method): void
    {
        if (! method_exists($handler, $method)) {
            throw new UndefinedHandlerMethodException($handler::class, $method);
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
        HandlerTarget $target,
    ): object {
        $interface = $target->interfaceClass();

        if (! isset($config[$interface]) || ! is_array($config[$interface])) {
            throw new MissingHandlerConfigurationException();
        }

        $classString = $config[$interface]['handler'];
        if (! is_string($classString)) {
            throw new InvalidHandlerClassDefinitionException(gettype($classString));
        }

        if (! is_subclass_of($classString, $interface)) {
            throw new InvalidHandlerImplementationException($classString, $interface);
        }

        return $this->handlerCache[$classString] ??= new $classString($manager);
    }

    /**
     * @param array<string,mixed> $config
     */
    private function isHandlerConfigured(array $config, HandlerTarget $target): bool
    {
        return isset($config[$target->interfaceClass()]);
    }

    /**
     * Resolves method arguments for the given handler type.
     *
     * @param array<string,mixed> $context
     * @param array<string,mixed> $config
     *
     * @return array{EncryptedJwtBundle, array<string,string>}
     */
    private function resolveArguments(
        HandlerTarget $target,
        array $context,
        array $config,
    ): array {
        /** @var EncryptedJwtBundle $bundle */
        $bundle = $context['bundle'];

        /** @var array<string,string> $methodConfig */
        $methodConfig = $config[$target->interfaceClass()];

        $handlerConf = [$bundle, $methodConfig];

        return match ($target) {
            HandlerTarget::Signature,
            HandlerTarget::Cek,
            HandlerTarget::Iv,
            HandlerTarget::Key,
            HandlerTarget::Payload => $handlerConf,
        };
    }
}
