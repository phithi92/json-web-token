<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler\Processor;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Handler\HandlerDescriptor;
use Phithi92\JsonWebToken\Handler\HandlerDispatcher;
use Phithi92\JsonWebToken\Handler\HandlerMethodResolver;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\HandlerType;
use Phithi92\JsonWebToken\Interfaces\JwtTokenOperation;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

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
        'cek' => [HandlerType::Cek, 10],
        'key' => [HandlerType::Key, 20],
        'iv' => [HandlerType::Iv, 30],
        'payload' => [HandlerType::Payload, 40],
        'signature' => [HandlerType::Signature, 50],
    ];

    /** @var HandlerOperation Encapsulates the operation mode (e.g., encrypt or decrypt). */
    protected readonly HandlerOperation $operation;

    /** @var JwtAlgorithmManager Manages algorithm-specific configurations. */
    protected readonly JwtAlgorithmManager $manager;

    /** @var HandlerDispatcher Responsible for invoking the correct handler methods. */
    protected readonly HandlerDispatcher $dispatcher;

    public function __construct(
        HandlerOperation $operation,
        JwtAlgorithmManager $manager
    ) {
        $this->manager = $manager;
        $this->operation = $operation;
        $this->dispatcher = new HandlerDispatcher(new HandlerMethodResolver());
    }

    /**
     * Returns the operation associated with the processor.
     */
    public function getOperation(): HandlerOperation
    {
        return $this->operation;
    }

    /**
     * Resolves the algorithm used for key decryption or encryption based on JWT headers.
     *
     * If 'alg' is 'dir' (direct symmetric key), falls back to 'enc' for further processing.
     *
     * @return string The resolved algorithm identifier.
     *
     * @throws InvalidTokenException If no algorithm is specified in the JWT header.
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
     * @param string $algorithm The resolved algorithm identifier.
     * @param EncryptedJwtBundle $bundle The encrypted JWT to process.
     */
    protected function dispatchHandlers(
        string $algorithm,
        EncryptedJwtBundle $bundle
    ): void {
        /** @var array<string,mixed> $config */
        /** @var array<int, HandlerDescriptor> $descriptors */
        [$config, $descriptors] = $this->resolveConfigAndHandlers($algorithm);

        foreach ($descriptors as $descriptor) {
            $this->dispatcher->dispatch(
                type: $descriptor->type,
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
     * @param string $algorithm The algorithm to use for configuration resolution.
     *
     * @return array{
     *     0: array<string, mixed>,
     *     1: array<int, HandlerDescriptor>
     * }
     */
    private function resolveConfigAndHandlers(string $algorithm): array
    {
        $config = $this->manager->getConfiguration($algorithm);
        $descriptors = $this->resolveApplicableHandlers($config);

        return [$config, $descriptors];
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
            if (isset($config[$type->interface()])) {
                $descriptors[] = new HandlerDescriptor($type, $this->getOperation(), $priority);
            }
        }

        return $this->orderByPriority($descriptors);
    }

    /**
     * Orders handler descriptors by ascending priority.
     *
     * @param array<int,HandlerDescriptor> $descriptors
     *
     * @return array<int,HandlerDescriptor> Sorted descriptor list.
     */
    private function orderByPriority(array $descriptors): array
    {
        usort($descriptors, static fn ($a, $b) => $a->priority <=> $b->priority);

        return $descriptors;
    }
}
