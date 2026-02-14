<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Pipeline;

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
     * @param array<string,mixed> $config
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
            throw new AlgorithmMethodNotFoundException($handler, $method);
        }

        $args = $this->resolveArguments($manager, $invocation, $jwtBundle, $config);

        /** @phpstan-ignore-next-line */
        return $handler->{$method}(...$args);
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
            throw new MissingAlgorithmConfigurationException($target->name);
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
        JwtKeyManager $manager,
        AlgorithmInvocation $invokation,
        JwtBundle $jwtBundle,
        array $config,
    ): array {
        /** @var array<string,string> $methodConfig */
        $methodConfig = $config[$invokation->target->interfaceClass()];

        return match ($invokation->target) {
            CryptoProcessingStage::Iv => $this->resolveIvArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Cek => $this->resolveCekArguments($jwtBundle, $methodConfig),
            CryptoProcessingStage::Key => $this->resolveKeyArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Signature => $this->resolveSignatureArguments($invokation->operation, $jwtBundle, $methodConfig),
            CryptoProcessingStage::Payload => $this->resolvePayloadArguments($invokation->operation, $jwtBundle, $methodConfig, $manager),
        };
    }

    private function resolveIvArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array {
        return match ($operation) {
            CryptoOperationDirection::Perform => [$methodConfig['length']],
            CryptoOperationDirection::Reverse => [
                $jwtBundle->getEncryption()->getIv(),
                (int) $methodConfig['length'],
            ],
        };
    }

    private function resolveCekArguments(
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array|string {
        return [
            $jwtBundle->getHeader()->getAlgorithm(),
            $methodConfig['length'] ?? 0,
        ];
    }

    private function resolveSignatureArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig
    ): array|string {
        return match ($operation) {
            CryptoOperationDirection::Perform => [
                (new DefaultKidResolver())->resolve($jwtBundle, $methodConfig),
                $methodConfig['hash_algorithm'],
                JwsSigningInput::fromBundle($jwtBundle),
            ],
            CryptoOperationDirection::Reverse => [
                (new DefaultKidResolver())->resolve($jwtBundle, $methodConfig),
                $methodConfig['hash_algorithm'],
                $jwtBundle->getEncryption()->getAad(),
                (string) $jwtBundle->getSignature(),
            ]
        };
    }

    private function resolvePayloadArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $methodConfig,
        JwtKeyManager $manager
    ): array|string {
        $cipherKeyLength = (int) $methodConfig['length'];

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

    private function resolveKeyArguments(
        CryptoOperationDirection $operation,
        JwtBundle $jwtBundle,
        array $config,
    ): array {
        return [
            $jwtBundle->getHeader()->getKid(),
            match ($operation) {
                CryptoOperationDirection::Reverse => $jwtBundle->getEncryption()->getEncryptedKey(),
                CryptoOperationDirection::Perform => $jwtBundle->getEncryption()->getCek()
            },
            $config['padding'] ?? null,
            $config['hash'] ?? null,
        ];
    }
}
