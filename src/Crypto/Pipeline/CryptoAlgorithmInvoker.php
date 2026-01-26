<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\AlgorithmMethodNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\InvalidAlgorithmImplementationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\MissingAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function gettype;
use function is_array;
use function is_string;
use function is_subclass_of;
use function method_exists;

final class CryptoAlgorithmInvoker
{
    /** @var array<class-string, object> */
    private array $handlerCache = [];

    public function __construct(
        private readonly AlgorithmMethodMap $methodResolver,
    ) {
    }

    /**
     * Dispatches a handler method call based on type and operation.
     *
     * @param array<string,mixed> $config
     * @param array<string,mixed> $context
     */
    public function dispatch(
        CryptoProcessingStage $target,
        CryptoOperationDirection $operation,
        JwtKeyManager $manager,
        array $config,
        array $context = [],
    ): mixed {
        if (! $this->isHandlerConfigured($config, $target)) {
            return null;
        }

        $handler = $this->buildHandler($config, $manager, $target);
        $method = $this->methodResolver->resolve($target, $operation);

        $this->assertValidHandlerMethod($handler, $method);

        $args = $this->resolveArguments($target, $context, $config);

        /** @phpstan-ignore-next-line */
        return $handler->{$method}(...$args);
    }

    /**
     * @throws AlgorithmMethodNotFoundException
     */
    private function assertValidHandlerMethod(object $handler, string $method): void
    {
        if (! method_exists($handler, $method)) {
            throw new AlgorithmMethodNotFoundException($handler::class, $method);
        }
    }

    /**
     * @param array<string,mixed> $config
     *
     * @throws MissingAlgorithmConfigurationException
     * @throws InvalidAlgorithmImplementationException
     */
    private function buildHandler(
        array $config,
        JwtKeyManager $manager,
        CryptoProcessingStage $target,
    ): object {
        $interface = $target->interfaceClass();

        if (! isset($config[$interface]) || ! is_array($config[$interface])) {
            throw new MissingAlgorithmConfigurationException();
        }

        $classString = $config[$interface]['handler'];
        if (! is_string($classString)) {
            throw new InvalidAlgorithmImplementationException(gettype($classString));
        }

        if (! is_subclass_of($classString, $interface)) {
            throw new InvalidAlgorithmImplementationException($classString);
        }

        return $this->handlerCache[$classString] ??= new $classString($manager);
    }

    /**
     * @param array<string,mixed> $config
     */
    private function isHandlerConfigured(array $config, CryptoProcessingStage $target): bool
    {
        return isset($config[$target->interfaceClass()]);
    }

    /**
     * Resolves method arguments for the given handler type.
     *
     * @param array<string,mixed> $context
     * @param array<string,mixed> $config
     *
     * @return array{JwtBundle, array<string,string>}
     */
    private function resolveArguments(
        CryptoProcessingStage $target,
        array $context,
        array $config,
    ): array {
        /** @var JwtBundle $bundle */
        $bundle = $context['bundle'];

        /** @var array<string,string> $methodConfig */
        $methodConfig = $config[$target->interfaceClass()];

        $arguments = [$bundle, $methodConfig];

        return match ($target) {
            CryptoProcessingStage::Signature,
            CryptoProcessingStage::Cek,
            CryptoProcessingStage::Iv,
            CryptoProcessingStage::Key,
            CryptoProcessingStage::Payload => $arguments,
        };
    }
}
