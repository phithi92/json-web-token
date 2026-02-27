<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use InvalidArgumentException;
use LogicException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\AlgorithmMethodNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\InvalidAlgorithmImplementationException;
use Phithi92\JsonWebToken\Exceptions\Crypto\Pipeline\MissingAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\DefaultKidResolver;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Serializer\JwsSigningInput;

use function gettype;
use function is_object;
use function is_string;
use function method_exists;
use function sprintf;
use function strlen;

/**
 * Invokes stage-specific crypto algorithm handlers.
 *
 * The invoker maps an AlgorithmInvocation (target stage + operation direction) to a concrete
 * handler method via AlgorithmMethodMap, builds the corresponding handler instance from the
 * provided configuration, and executes the resolved method with validated arguments.
 *
 * Key points:
 * - Fast capability check via isSupported() before attempting execution.
 * - Handler instances may be cached by class-string to reduce instantiation overhead.
 * - Configuration is validated early; missing stage configuration results in an exception.
 * - The resolved handler method must exist; otherwise an exception is thrown.
 */
final class CryptoAlgorithmInvoker
{
    /** @var array<class-string, object> */
    private array $handlerCache = [];

    public function __construct(
        private readonly AlgorithmMethodMap $methodResolver,
    ) {
    }

    /**
     * Determines whether a handler method is configured for the given processing stage and operation direction.
     *
     * @return bool True if a matching handler method is configured; otherwise false.
     */
    public function isSupported(AlgorithmInvocation $invokation): bool
    {
        return $this->methodResolver->supports($invokation);
    }

    /**
     * Dispatches a handler method call based on type and operation.
     *
     * @param array<string, array<string,mixed>> $config
     *
     * @throws MissingAlgorithmConfigurationException
     * @throws AlgorithmMethodNotFoundException
     */
    public function process(
        AlgorithmInvocation $invocation,
        JwtKeyManager $manager,
        JwtBundle $jwtBundle,
        array $config,
    ): ?CryptoStageResultInterface {
        // check if handler config exist
        if (! isset($config[$invocation->target->interfaceClass()])) {
            throw new MissingAlgorithmConfigurationException($invocation->target->name);
        }

        $args = $this->resolveArguments($manager, $invocation, $jwtBundle, $config);
        $handler = $this->buildHandler($manager, $invocation, $config);
        $method = $this->methodResolver->resolve($invocation) ?? '';

        if (! method_exists($handler, $method)) {
            throw new AlgorithmMethodNotFoundException($invocation, $method);
        }

        $result = $handler->{$method}(...$args);

        if (! $result instanceof CryptoStageResultInterface && $result !== null) {
            throw new LogicException(sprintf(
                'Invalid handler return type: expected null or an instance of %s, got %s from %s::%s (stage: %s, operation: %s).',
                CryptoStageResultInterface::class,
                is_object($result) ? $result::class : gettype($result),
                $handler::class,
                $method,
                $invocation->target->name,
                $invocation->operation->name,
            ));
        }

        return $result;
    }

    /**
     * Builds and returns a cryptographic handler for the given stage.
     *
     * This method resolves the handler class from the provided configuration,
     * validates it, caches it, and ensures it implements the expected interface.
     *
     * @param JwtKeyManager $manager The key manager used to construct handler instances
     * @param AlgorithmInvocation $invocation The invocation containing the target stage
     * @param array<string,array<mixed>>$config Configuration mapping interface names to handler classes
     *
     * @return object An instance of the handler implementing the interface for the target stage
     *
     * @throws MissingAlgorithmConfigurationException If no configuration exists for the target interface
     * @throws InvalidAlgorithmImplementationException If the resolved handler class is invalid or does not implement the expected interface
     */
    private function buildHandler(
        JwtKeyManager $manager,
        AlgorithmInvocation $invocation,
        array $config
    ): object {
        $interfaceName = $invocation->target->interfaceClass();
        if (! isset($config[$interfaceName])) {
            throw new MissingAlgorithmConfigurationException($invocation->target->name);
        }

        $className = $config[$interfaceName]['handler'] ?? null;
        if (! is_string($className)) {
            throw new InvalidAlgorithmImplementationException(gettype($className));
        }

        if (isset($this->handlerCache[$className])) {
            return $this->handlerCache[$className];
        }

        $class = new $className($manager);
        if (! $class instanceof $interfaceName) {
            throw new InvalidAlgorithmImplementationException($className);
        }
        
        return $this->handlerCache[$className] = $class;
    }

    /**
     * Resolves method arguments for the given handler type.
     *
     * @param array<string, array<string,mixed>> $config
     *
     * @return array<int, string|int|null>
     */
    private function resolveArguments(
        JwtKeyManager $manager,
        AlgorithmInvocation $invokation,
        JwtBundle $jwtBundle,
        array $config,
    ): array {
        $methodConfig = $config[$invokation->target->interfaceClass()];

        return match ($invokation->target) {
            CryptoProcessingStage::Iv => $this->resolveIvArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Cek => $this->resolveCekArguments($jwtBundle, $methodConfig),
            CryptoProcessingStage::Key => $this->resolveKeyArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Signature => $this->resolveSignatureArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Payload => $this->resolvePayloadArguments($invokation->operation, $jwtBundle, $methodConfig, $manager),
        };
    }

    /**
     * @param array<string, mixed> $methodConfig
     *
     * @return array<int,string|int>
     */
    private function resolveIvArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array {
        $length = $this->resolveLength($methodConfig['length']);

        return match ($operation) {
            CryptoOperationDirection::Perform => [$length],
            CryptoOperationDirection::Reverse => [
                $jwtBundle->getEncryption()->getIv(),
                $length,
            ],
        };
    }

    /**
     * @param array<string, mixed> $methodConfig
     *
     * @return array<int,string|int|null>
     */
    private function resolveCekArguments(
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array {
        $length = $this->resolveLength($methodConfig['length']);

        return [
            $jwtBundle->getHeader()->getAlgorithm(),
            $length,
        ];
    }

    /**
     * @param array<string, mixed> $methodConfig
     *
     * @return array<int,string|int|null>
     */
    private function resolveSignatureArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array {
        $algorithm = $this->resolveOptionalConfig($methodConfig, 'hash_algorithm');

        return match ($operation) {
            CryptoOperationDirection::Perform => [
                (new DefaultKidResolver())->resolve($jwtBundle, $methodConfig),
                $algorithm,
                JwsSigningInput::fromBundle($jwtBundle),
            ],
            CryptoOperationDirection::Reverse => [
                (new DefaultKidResolver())->resolve($jwtBundle, $methodConfig),
                $algorithm,
                $jwtBundle->getEncryption()->getAad(),
                (string) $jwtBundle->getSignature(),
            ]
        };
    }

    /**
     * @param array<string, mixed> $methodConfig
     *
     * @return array<int,string|int>
     */
    private function resolvePayloadArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig,
        JwtKeyManager $manager
    ): array {
        $cipherKeyLength = $this->resolveLength($methodConfig['length']);

        $passphrase = $jwtBundle->getHeader()->getAlgorithm() === 'dir'
            ? $manager->getPassphrase($jwtBundle->getHeader()->getKid())
            : $jwtBundle->getEncryption()->getCek();

        if ($jwtBundle->getHeader()->getAlgorithm() === 'dir') {
            $this->assertDirectEncryptionKeyLength($passphrase, $cipherKeyLength);
        }

        return match ($operation) {
            CryptoOperationDirection::Perform => [
                JwtPayloadJsonCodec::encodeStatic($jwtBundle->getPayload()),
                $passphrase,
                $cipherKeyLength,
                $jwtBundle->getEncryption()->getIv(),
                $jwtBundle->getEncryption()->getAad(),
            ],
            CryptoOperationDirection::Reverse => [
                $jwtBundle->getPayload()->getEncryptedPayload(),
                $passphrase,
                $cipherKeyLength,
                $jwtBundle->getEncryption()->getIv(),
                $jwtBundle->getEncryption()->getAuthTag(),
                $jwtBundle->getEncryption()->getAad(),
            ]
        };
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<int,string|int|null>
     */
    private function resolveKeyArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $config,
    ): array {
        $padding = $this->resolveOptionalConfig($config, 'padding');
        $hash = $this->resolveOptionalConfig($config, 'hash');

        return [
            $jwtBundle->getHeader()->getKid(),
            match ($operation) {
                CryptoOperationDirection::Reverse => $jwtBundle->getEncryption()->getEncryptedKey(),
                CryptoOperationDirection::Perform => $jwtBundle->getEncryption()->getCek()
            },
            $padding,
            $hash,
        ];
    }

    private function assertDirectEncryptionKeyLength(string $key, int $cipherKeyLength): void
    {
        $expectedLength = intdiv($cipherKeyLength, 8);
        $actualLength = strlen($key);

        if ($actualLength !== $expectedLength) {
            throw new InvalidTokenException(sprintf(
                'Invalid direct encryption key length (got %d bytes, expected %d bytes)',
                $actualLength,
                $expectedLength
            ));
        }
    }

    private function resolveLength(mixed $length): int
    {
        if (is_int($length)) {
            return $length;
        }

        if (! is_string($length)) {
            throw new InvalidArgumentException(sprintf(
                'Length must be int or string, %s given',
                get_debug_type($length)
            ));
        }

        $intLength = filter_var($length, FILTER_VALIDATE_INT);

        if ($intLength === false) {
            throw new InvalidArgumentException(sprintf(
                'Length string must be numeric, "%s" given',
                $length
            ));
        }

        return $intLength;
    }

    /**
     * Safely extracts optional configuration with type enforcement.
     *
     * @param array<string, mixed> $config
     */
    private function resolveOptionalConfig(array $config, string $key): string|int|null
    {
        if (! array_key_exists($key, $config)) {
            return null;
        }

        $value = $config[$key];

        return match (true) {
            $value === null => null,
            is_string($value) => $value,
            is_int($value) => $value,
            default => throw new InvalidArgumentException(sprintf(
                'Config "%s" must be string|int|null, got %s',
                $key,
                get_debug_type($value)
            )),
        };
    }
}
