<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Processor;

use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmInvocation;
use Phithi92\JsonWebToken\Crypto\Pipeline\AlgorithmMethodMap;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoAlgorithmInvoker;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoProcessingStage;
use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoStageResultDispatcher;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;

use function usort;

/**
 * Abstract base class for processing JWT tokens using a defined set of handlers and operations.
 *
 * Implements the JwtTokenOperation interface and provides common functionality for resolving
 * algorithms and dispatching handlers.
 */
abstract class AbstractJwtTokenProcessor implements JwtTokenOperation
{
    /** @var CryptoOperationDirection Encapsulates the operation mode (e.g., encrypt or decrypt). */
    public readonly CryptoOperationDirection $operation;

    /** @var CryptoAlgorithmInvoker Responsible for invoking the correct handler methods. */
    protected readonly CryptoAlgorithmInvoker $dispatcher;

    /** @var JwtKeyManager Manages algorithm-specific configurations. */
    protected readonly JwtKeyManager $manager;

    protected readonly CryptoStageResultDispatcher $resultDispatcher;

    /**
     * Creates a JWT token processor for the given operation mode.
     *
     * @param CryptoOperationDirection $operation The operation to perform (e.g. encrypt or decrypt).
     * @param JwtKeyManager    $manager   Provides algorithm-specific configuration and keys.
     */
    public function __construct(
        CryptoOperationDirection $operation,
        JwtKeyManager $manager,
    ) {
        $this->manager = $manager;
        $this->operation = $operation;
        $this->dispatcher = new CryptoAlgorithmInvoker(new AlgorithmMethodMap());
        $this->resultDispatcher = new CryptoStageResultDispatcher();
    }

    /**
     * Resolves the algorithm used for key decryption or encryption based on JWT headers.
     *
     * If 'alg' is 'dir' (direct symmetric key), falls back to 'enc' for further processing.
     *
     * @return string the resolved algorithm identifier
     *
     * @throws InvalidTokenException if no algorithm is specified in the JWT header
     */
    protected function resolveAlgorithm(JwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $alg = $header->getAlgorithm() ?? throw new InvalidTokenException('No algorithm configured');

        $enc = $header->getEnc();
        if ($enc === null) {
            return $alg;
        }

        if ($alg === 'dir') {
            return $enc;
        }

        $combined = sprintf('%s/%s', $alg, $enc);

        if ($this->manager->getConfiguration($combined) === []) {
            throw new InvalidTokenException(
                sprintf('Unsupported algorithm combination: %s', $combined)
            );
        }

        return $combined;
    }

    /**
     * Dispatches all applicable handlers for the given JWT bundle and algorithm.
     *
     * Resolves the algorithm-specific configuration and its applicable handlers,
     * then dispatches them in priority order.
     *
     * @param string   $algorithm the resolved algorithm identifier
     * @param JwtBundle $jwtBundle   the JWT bundle to process
     */
    protected function dispatchHandlers(
        string $algorithm,
        JwtBundle $jwtBundle,
    ): JwtBundle {
        [$config, $descriptors] = $this->resolveConfigAndHandlers($algorithm);
        $processedBundle = $jwtBundle;

        foreach ($descriptors as $descriptor) {

            if ($this->dispatcher->isSupported($descriptor)) {
                $result = $this->dispatcher->process(
                    invocation: $descriptor,
                    manager: $this->manager,
                    jwtBundle: $processedBundle,
                    config: $config,
                );
            }

            if ($this->resultDispatcher->isSupported($descriptor) && $result !== null) {
                $processedBundle = $this->resultDispatcher->process(
                    invocation: $descriptor,
                    bundle: $processedBundle,
                    result: $result,
                );
            }
        }

        return $processedBundle;
    }

    /**
     * Resolves both the algorithm configuration and the corresponding handler descriptors.
     *
     * The configuration is always retrieved from the manager, and handler descriptors are
     * rebuilt on every call to avoid stale handler lists when config changes dynamically.
     *
     * @param string $algorithm the algorithm to use for configuration resolution
     *
     * @return array{array<string, mixed>, array<int, AlgorithmInvocation>}
     */
    private function resolveConfigAndHandlers(string $algorithm): array
    {
        $config = $this->manager->getConfiguration($algorithm);
        $descriptors = $this->resolveApplicableHandlers($config);

        return [$config, $descriptors];
    }

    /**
     * Builds an ordered list of handler descriptors based on the available config keys.
     *
     * Only targets whose interface class is present in the configuration are included.
     * The resulting list is sorted by {@see AlgorithmInvocation::$priority}.
     *
     * @param array<string, mixed> $config
     *
     * @return array<int, AlgorithmInvocation>
     */
    private function resolveApplicableHandlers(array $config): array
    {
        $descriptors = [];

        foreach (CryptoProcessingStage::cases() as $target) {
            if (! isset($config[$target->interfaceClass()])) {
                continue;
            }

            $descriptors[] = new AlgorithmInvocation(
                $target,
                $this->operation,
                $target->priority()
            );
        }

        usort($descriptors, static fn ($a, $b) => $a->priority <=> $b->priority);

        return $descriptors;
    }
}
