<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Processor;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Handler\HandlerDescriptor;
use Phithi92\JsonWebToken\Handler\HandlerDispatcher;
use Phithi92\JsonWebToken\Handler\HandlerMethodResolver;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\HandlerTarget;
use Phithi92\JsonWebToken\Interfaces\JwtTokenOperation;
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
    /** @var HandlerOperation Encapsulates the operation mode (e.g., encrypt or decrypt). */
    public readonly HandlerOperation $operation;

    /** @var HandlerDispatcher Responsible for invoking the correct handler methods. */
    protected readonly HandlerDispatcher $dispatcher;
    
    /** @var JwtKeyManager Manages algorithm-specific configurations. */
    protected readonly JwtKeyManager $manager;

    /**
     * Creates a JWT token processor for the given operation mode.
     *
     * @param HandlerOperation $operation The operation to perform (e.g. encrypt or decrypt).
     * @param JwtKeyManager    $manager   Provides algorithm-specific configuration and keys.
     */
    public function __construct(
        HandlerOperation $operation,
        JwtKeyManager $manager,
    ) {
        $this->manager = $manager;
        $this->operation = $operation;
        $this->dispatcher = new HandlerDispatcher(new HandlerMethodResolver());
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
        $alg = $header->getAlgorithm() ?? throw new InvalidTokenException('no algorithm');

        return $alg === 'dir' && $header->getEnc() !== null ? $header->getEnc() : $alg;
    }

    /**
     * Dispatches all applicable handlers for the given JWT bundle and algorithm.
     *
     * Resolves the algorithm-specific configuration and its applicable handlers,
     * then dispatches them in priority order.
     *
     * @param string   $algorithm the resolved algorithm identifier
     * @param JwtBundle $bundle   the JWT bundle to process
     */
    protected function dispatchHandlers(
        string $algorithm,
        JwtBundle $bundle,
    ): void {
        [$config, $descriptors] = $this->resolveConfigAndHandlers($algorithm);

        foreach ($descriptors as $descriptor) {
            $this->dispatcher->dispatch(
                target: $descriptor->target,
                operation: $descriptor->operation,
                manager: $this->manager,
                config: $config,
                context: [
                    'bundle' => $bundle,
                    'config' => $config,
                ]
            );
        }
    }

    /**
     * Resolves both the algorithm configuration and the corresponding handler descriptors.
     *
     * The configuration is always retrieved from the manager, and handler descriptors are
     * rebuilt on every call to avoid stale handler lists when config changes dynamically.
     *
     * @param string $algorithm the algorithm to use for configuration resolution
     *
     * @return array{array<string, mixed>, array<int, HandlerDescriptor>}
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
     * The resulting list is sorted by {@see HandlerDescriptor::$priority}.
     *
     * @param array<string, mixed> $config
     *
     * @return array<int, HandlerDescriptor>
     */
    private function resolveApplicableHandlers(array $config): array
    {
        $descriptors = [];

        foreach (HandlerTarget::cases() as $target) {
            if (! isset($config[$target->interfaceClass()])) {
                continue;
            }

            $descriptors[] = new HandlerDescriptor(
                $target,
                $this->operation,
                $target->priority()
            );
        }

        usort($descriptors, static fn ($a, $b) => $a->priority <=> $b->priority);

        return $descriptors;
    }
}
