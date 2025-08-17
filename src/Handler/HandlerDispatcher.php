<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerClassDefinitionException;
use Phithi92\JsonWebToken\Exceptions\Handler\InvalidHandlerImplementationException;
use Phithi92\JsonWebToken\Exceptions\Handler\MissingHandlerConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Handler\UndefinedHandlerMethodException;
use Phithi92\JsonWebToken\Factory\ClassFactory;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use RuntimeException;

final class HandlerDispatcher
{
    private HandlerInvoker $invoker;

    public function __construct(
        private readonly HandlerMethodResolver $methodResolver,
    ) {
        $this->invoker = new HandlerInvoker();
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

        return $this->invoker->invoke($handler, $method, $args);
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
        HandlerType $type
    ): object {
        $interface = $type->interface();

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

        $factory = new ClassFactory();
        return $factory->create($classString, [$manager]);
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
