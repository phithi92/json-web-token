<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use LogicException;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionKeyManagerInterface;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionManagerInterface;
use Phithi92\JsonWebToken\Interfaces\InitializationVectorManagerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyManagementManagerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureManagerInterface;

final class JwtTokenBuilder
{
    private readonly JwtAlgorithmManager $manager;
    private readonly JwtValidator $validator;

    public function __construct(
        JwtAlgorithmManager $manager,
        ?JwtValidator $validator
    ) {
        $this->manager = $manager;
        $this->validator = $validator ?? new JwtValidator();
    }

    public function create(JwtPayload $payload, string $algorithm, ?string $kid = null): EncryptedJwtBundle
    {
        $this->validator->assertValid($payload);
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

        $tokenType = $config['token_type'] ?? null;
        $algorithmName = $config['alg'] ?? null;

        if (! is_string($tokenType) || ! is_string($algorithmName)) {
            throw new LogicException('Invalid algorithm configuration');
        }

        $resolvedKid = $kid ?? $algorithm;
        $jwtHeader = $this->createHeader($tokenType, $algorithmName, $resolvedKid, $config);
        $jwtBundle = new EncryptedJwtBundle($jwtHeader, $payload);

        foreach ($this->getHandlerMappings() as $key => [$interface, $method]) {
            $this->applyHandler($jwtBundle, $config, $key, $interface, $method);
        }

        return $jwtBundle;
    }

    /**
     * Erstellt den Header basierend auf Config und Parametern.
     *
     * @param array<string, array<string,string>|string> $config
     */
    private function createHeader(string $type, string $alg, string $kid, array $config): JwtHeader
    {
        $header = new JwtHeader();
        $header->setType($type);
        $header->setAlgorithm($alg);
        $header->setKid($kid);

        if (isset($config['enc']) && is_string($config['enc'])) {
            $header->setEnc($config['enc']);
        }

        return $header;
    }

    /**
     * Handler-Mapping-Konfiguration: [config-key => [Interface, Methode]]
     *
     * @return array<string, array{class-string, string}>
     */
    private function getHandlerMappings(): array
    {
        return [
            'cek' => [ContentEncryptionKeyManagerInterface::class, 'initializeCek'],
            'key_management' => [KeyManagementManagerInterface::class, 'wrapKey'],
            'signing_algorithm' => [SignatureManagerInterface::class, 'computeSignature'],
            'iv' => [InitializationVectorManagerInterface::class, 'initializeIv'],
            'content_encryption' => [ContentEncryptionManagerInterface::class, 'encryptPayload'],
        ];
    }

    /**
     * Ruft Handler auf, falls konfiguriert.
     *
     * @template T of object
     *
     * @param array<string, mixed> $config
     * @param class-string<T> $interface
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
     * @param array<string, array<string, string>|string> $config
     * @param class-string<T> $interface
     *
     * @return T
     */
    private function resolveHandler(array $config, string $key, string $interface): object
    {
        return \Phithi92\JsonWebToken\Core\HandlerResolver::resolve(
            $config,
            $key,
            $interface,
            $this->manager
        );
    }
}
