<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Crypto\ContentEncryption\ContentEncryptionHandlerInterface;
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
use function is_array;
use function is_string;
use function is_subclass_of;
use function method_exists;
use function sprintf;
use function strlen;

final class CryptoAlgorithmInvoker
{
    /** @var array<class-string, object> */
    private array $handlerCache = [];

    public function __construct(
        private readonly AlgorithmMethodMap $methodResolver,
    ) {
    }

    /**
     *
     * @param AlgorithmInvocation $invokation
     *
     * @return bool
     */
    public function isSupported(AlgorithmInvocation $invokation): bool
    {
        return $this->methodResolver->supports(
            $invokation->target,
            $invokation->operation
        );
    }

    /**
     * Dispatches a handler method call based on type and operation.
     *
     * @param AlgorithmInvocation $invocation
     * @param JwtKeyManager $manager
     * @param JwtBundle $jwtBundle
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
    ): mixed {
        if (! $this->isHandlerConfigured($config, $invocation->target)) {
            throw new MissingAlgorithmConfigurationException($invocation->target->name);
        }

        $method = $this->methodResolver->resolve($invocation->target, $invocation->operation);

        $handler = $this->buildHandler($config, $manager, $invocation->target);

        if (! method_exists($handler, $method)) {
            throw new AlgorithmMethodNotFoundException($invocation->target, $invocation->operation);
        }

        $args = $this->resolveArguments($manager, $invocation, $jwtBundle, $config);

        /** @phpstan-ignore-next-line */
        return $handler->{$method}(...$args);
    }

    /**
     * @param array<string,mixed> $config
     * @param JwtKeyManager $manager
     * @param CryptoProcessingStage $target
     *
     * @return object
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
            throw new MissingAlgorithmConfigurationException($target->name);
        }

        $classString = $config[$interface]['handler'];
        if (! is_string($classString)) {
            throw new InvalidAlgorithmImplementationException(gettype($classString));
        }

        if (! is_subclass_of($classString, $interface)) {
            throw new InvalidAlgorithmImplementationException($classString);
        }

        if (is_subclass_of($classString, ContentEncryptionHandlerInterface::class)) {
            $this->handlerCache[$classString] ??= new $classString();
        }

        return $this->handlerCache[$classString] ??= new $classString($manager);
    }

    /**
     * @param array<string,array<string,mixed>> $config
     */
    private function isHandlerConfigured(array $config, CryptoProcessingStage $target): bool
    {
        return isset($config[$target->interfaceClass()]);
    }

    /**
     * Resolves method arguments for the given handler type.
     *
     * @param JwtKeyManager $manager
     * @param AlgorithmInvocation $invokation
     * @param JwtBundle $jwtBundle
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
     *
     * @param CryptoOperationDirection $operation
     * @param JwtBundle $jwtBundle
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
     *
     * @param JwtBundle $jwtBundle
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
     *
     * @param CryptoOperationDirection $operation
     * @param JwtBundle $jwtBundle
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
     *
     * @param CryptoOperationDirection $operation
     * @param JwtBundle $jwtBundle
     * @param array<string, mixed> $methodConfig
     * @param JwtKeyManager $manager
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
     *
     * @param CryptoOperationDirection $operation
     * @param JwtBundle $jwtBundle
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

        if (!is_string($length)) {
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
        if (!array_key_exists($key, $config)) {
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
