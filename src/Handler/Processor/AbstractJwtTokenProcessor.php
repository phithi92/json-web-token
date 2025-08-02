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

abstract class AbstractJwtTokenProcessor implements JwtTokenOperation
{
    public const OPERATION = null;

    private const array HANDLER_CONFIG_MAP = [
        'cek' => [HandlerType::Cek, 10],
        'key' => [HandlerType::Key, 20],
        'iv' => [HandlerType::Iv, 30],
        'payload' => [HandlerType::Payload, 40],
        'signature' => [HandlerType::Signature, 50],
    ];

    /**
     * @var JwtAlgorithmManager Handles algorithm resolution and handler configuration.
     */
    protected readonly JwtAlgorithmManager $manager;
    protected readonly HandlerDispatcher $dispatcher;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
        $this->dispatcher = new HandlerDispatcher(new HandlerMethodResolver());
    }

    public function getOperation(): HandlerOperation
    {
        return static::OPERATION;
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

    protected function dispatchHandlers(
        EncryptedJwtBundle $bundle,
        string $algorithm
    ): void {
        $config = $this->manager->getConfiguration($algorithm);
        $descriptors = $this->resolveApplicableHandlers($config);

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
     * Builds a list of handler descriptors based on available config keys.
     *
     * @param array<string, mixed> $config
     *
     * @return array<HandlerDescriptor>
     */
    private function resolveApplicableHandlers(array $config): array
    {
        $descriptors = [];

        foreach (self::HANDLER_CONFIG_MAP as [$type, $priority]) {
            if (isset($config[$type->interface()])) {
                $descriptors[] = new HandlerDescriptor($type, $this->getOperation(), $priority);
            }
        }

        usort($descriptors, static fn ($a, $b) => $a->priority <=> $b->priority);

        return $descriptors;
    }
}
