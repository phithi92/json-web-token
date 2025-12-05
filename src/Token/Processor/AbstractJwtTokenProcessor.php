<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Processor;

use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Handler\HandlerDescriptor;
use Phithi92\JsonWebToken\Handler\HandlerDispatcher;
use Phithi92\JsonWebToken\Handler\HandlerMethodResolver;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\HandlerTarget;
use Phithi92\JsonWebToken\Interfaces\JwtTokenOperation;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

use function usort;

/**
 * Abstract base class for processing JWT tokens using a defined set of handlers and operations.
 *
 * Implements the JwtTokenOperation interface and provides common functionality for resolving
 * algorithms and dispatching handlers.
 */
abstract class AbstractJwtTokenProcessor implements JwtTokenOperation
{
    /**
     * Maps JWT component keys to handler types and priorities.
     *
     * The integer values define execution order (lower = earlier).
     */
    private const HANDLER_CONFIG_MAP = [
        [HandlerTarget::Cek, 1],
        [HandlerTarget::Key, 2],
        [HandlerTarget::Iv, 3],
        [HandlerTarget::Payload, 4],
        [HandlerTarget::Signature, 5],
    ];

    /** @var HandlerOperation Encapsulates the operation mode (e.g., encrypt or decrypt). */
    public readonly HandlerOperation $operation;

    /** @var JwtAlgorithmManager Manages algorithm-specific configurations. */
    protected readonly JwtAlgorithmManager $manager;

    /** @var HandlerDispatcher Responsible for invoking the correct handler methods. */
    protected readonly HandlerDispatcher $dispatcher;

    /**
     * Caches resolved configurations and handler descriptors per algorithm to
     * avoid rebuilding immutable structures on repeated invocations.
     *
     * @var array<string,array<int,HandlerDescriptor>>
     */
    private array $resolvedHandlerCache = [];

    public function __construct(
        HandlerOperation $operation,
        JwtAlgorithmManager $manager,
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
    protected function resolveAlgorithm(EncryptedJwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $alg = $header->getAlgorithm() ?? throw new InvalidTokenException('no algorithm');

        return $alg === 'dir' && $header->getEnc() !== null ? $header->getEnc() : $alg;
    }

    /**
     * Dispatches all applicable handlers for the given JWT bundle and algorithm.
     *
     * Resolves configuration and handlers based on the provided algorithm, and
     * executes them in order of their defined priority.
     *
     * @param string             $algorithm the resolved algorithm identifier
     * @param EncryptedJwtBundle $bundle    the encrypted JWT to process
     */
    protected function dispatchHandlers(
        string $algorithm,
        EncryptedJwtBundle $bundle,
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
     * Resolves both the handler configuration and corresponding handler descriptors.
     *
     * @param string $algorithm the algorithm to use for configuration resolution
     *
     * @return array{array<string, mixed>, array<int,HandlerDescriptor>}
     */
    private function resolveConfigAndHandlers(string $algorithm): array
    {
        $config = $this->manager->getConfiguration($algorithm);
        if (! isset($this->resolvedHandlerCache[$algorithm])) {
            $this->resolvedHandlerCache[$algorithm] = $this->resolveApplicableHandlers($config);
        }

        // Return a fresh configuration array on every call to avoid leaking
        // mutations between requests, while still reusing descriptor metadata.
        return [$config, $this->resolvedHandlerCache[$algorithm]];
    }

    /**
     * Builds a list of handler descriptors based on available config keys.
     *
     * @param array<string, mixed> $config
     *
     * @return array<int,HandlerDescriptor>
     */
    private function resolveApplicableHandlers(array $config): array
    {
        $descriptors = [];

        foreach (self::HANDLER_CONFIG_MAP as [$type, $priority]) {
            if (isset($config[$type->interfaceClass()])) {
                $descriptors[] = new HandlerDescriptor($type, $this->operation, $priority);
            }
        }

        return $this->orderByPriority($descriptors);
    }

    /**
     * Orders handler descriptors by ascending priority.
     *
     * @param array<int,HandlerDescriptor> $descriptors
     *
     * @return array<int,HandlerDescriptor> sorted descriptor list
     */
    private function orderByPriority(array $descriptors): array
    {
        usort($descriptors, static fn ($a, $b) => $a->priority <=> $b->priority);

        return $descriptors;
    }
}
