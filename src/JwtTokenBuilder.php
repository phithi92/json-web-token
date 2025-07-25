<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

final class JwtTokenBuilder
{
    private const HANDLER_MAPPINGS = [
        'cek' => [
            CekHandlerInterface::class,
            'initializeCek',
        ],
        'key_management' => [
            KeyHandlerInterface::class,
            'wrapKey',
        ],
        'signing_algorithm' => [
            SignatureHandlerInterface::class,
            'computeSignature',
        ],
        'iv' => [
            IvHandlerInterface::class,
            'initializeIv',
        ],
        'content_encryption' => [
            PayloadHandlerInterface::class,
            'encryptPayload',
        ],
    ];
    private readonly JwtAlgorithmManager $manager;

    public function __construct(
        JwtAlgorithmManager $manager
    ) {
        $this->manager = $manager;
    }

    public function create(JwtPayload $payload, string $algorithm, ?string $kid = null): EncryptedJwtBundle
    {
        return $this->createWithoutValidation($payload, $algorithm, $kid);
    }

    /**
     * ❌ Do NOT use this method in production code.
     * ❌ It disables claim and context verification.
     *
     * @throws LogicException
     */
    public function createWithoutValidation(
        JwtPayload $payload,
        string $algorithm,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        [$typ,$alg,$enc] = $this->extractHeaderParams($config);

        $header = $this->createHeader($typ, $alg, $kid, $enc);
        $bundle = new EncryptedJwtBundle($header, $payload);

        foreach (self::HANDLER_MAPPINGS as $key => [$interface, $method]) {
            $this->applyHandler($bundle, $config, $key, $interface, $method);
        }

        return $bundle;
    }
    
    /**
     * 
     * @param array $config
     * @return array{string,string|null,string|null}
     * @throws LogicException
     */
    private function extractHeaderParams(array $config):array
    {
        if (!isset($config['token_type'], $config['alg'])) {
            throw new LogicException('Incomplete algorithm configuration');
        }
        
        return [
            $config['token_type'],
            $config['alg'] ?? null,
            $config['enc'] ?? null
        ];
    }

    /**
     * Create header on config and params
     */
    private function createHeader(string $typ, string $alg, ?string $kid, ?string $enc): JwtHeader
    {
        $header = (new JwtHeader())->setType($typ)->setAlgorithm($alg);

        $kid ??= $this->buildDefaultKid($alg, $enc);
        if (! $this->manager->hasKey($kid) && ! $this->manager->hasPassphrase($kid)) {
            throw new UnresolvableKeyException($kid);
        }

        return $header->setKid($kid);
    }

    private function buildDefaultKid(string $alg, ?string $enc): string
    {
        $parts = [];

        if (strtolower($alg) !== 'dir') {
            $parts[] = $alg;
        }

        if ($enc !== null && $enc !== '') {
            $parts[] = $enc;
        }

        return implode('_', $parts);
    }

    /**
     * Run handler when configured.
     *
     * @template T of object
     *
     * @param array<string, mixed> $config
     * @param class-string<T>      $interface
     */
    private function applyHandler(
        EncryptedJwtBundle $bundle,
        array $config,
        string $key,
        string $interface,
        string $method
    ): void {
        if (! isset($config[$key]) || ! is_array($config[$key])) {
            return;
        }

        $handler = $this->resolveHandler($config, $key, $interface);
        $handler->{$method}($bundle, $config[$key]);
    }

    /**
     * @template T of object
     *
     * @param array<string, mixed> $config
     * @param class-string<T>      $interface
     *
     * @return T
     */
    private function resolveHandler(array $config, string $key, string $interface): object
    {
        return HandlerResolver::resolve(
            $config,
            $key,
            $interface,
            $this->manager
        );
    }
}
