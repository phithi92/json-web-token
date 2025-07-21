<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use LogicException;
use Phithi92\JsonWebToken\Core\HandlerResolver;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

final class JwtTokenBuilder
{
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

        $typ = $config['token_type'];
        $alg = $config['alg'] ?? null;
        /** @var string $enc */
        $enc = $config['enc'] ?? null;

        if (! is_string($typ) || ! is_string($alg)) {
            throw new LogicException('Invalid algorithm configuration');
        }

        $header = $this->createHeader($typ, $alg, $kid, $enc);
        $bundle = new EncryptedJwtBundle($header, $payload);

        foreach ($this->getHandlerMappings() as $key => [$interface, $method]) {
            $this->applyHandler($bundle, $config, $key, $interface, $method);
        }

        return $bundle;
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
     * Handler-Mapping-Konfiguration: [config-key => [Interface, Methode]]
     *
     * @return array<string, array{class-string, string}>
     */
    private function getHandlerMappings(): array
    {
        return [
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
