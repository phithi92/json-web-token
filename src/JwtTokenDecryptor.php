<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Core\HandlerResolver;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionKeyManagerInterface;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionManagerInterface;
use Phithi92\JsonWebToken\Interfaces\InitializationVectorManagerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyManagementManagerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureManagerInterface;

final class JwtTokenDecryptor
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

    public function decrypt(string $token): EncryptedJwtBundle
    {
        $bundle = $this->decryptWithoutValidation($token);
        $this->validator->assertValidBundle($bundle);
        return $bundle;
    }

    public function decryptWithoutValidation(string $token): EncryptedJwtBundle
    {
        $bundle = JwtTokenParser::parse($token);

        $algorithm = $this->resolveAlgorithm($bundle);

        $config = $this->manager->getConfiguration($algorithm);

        foreach ($this->getHandlerMappings() as $key => [$interface, $method]) {
            /** @var class-string<object> $interface */
            $this->applyHandler($bundle, $config, $key, $interface, $method);
        }

        return $bundle;
    }

    private function resolveAlgorithm(EncryptedJwtBundle $bundle): string
    {
        $header = $bundle->getHeader();
        $alg = $header->getAlgorithm() ?? throw new \Exception('no algorithm');

        return $alg === 'dir' && $header->getEnc() !== null
            ? $header->getEnc()
            : $alg;
    }

    /**
     * @return array<string, array<string>>
     */
    private function getHandlerMappings(): array
    {
        return [
            'key_management' => [KeyManagementManagerInterface::class, 'unwrapKey'],
            'cek' => [ContentEncryptionKeyManagerInterface::class, 'validateCek'],
            'iv' => [InitializationVectorManagerInterface::class, 'validateIv'],
            'signing_algorithm' => [SignatureManagerInterface::class, 'validateSignature'],
            'content_encryption' => [ContentEncryptionManagerInterface::class, 'decryptPayload'],
        ];
    }

    /**
     * Applies a handler to the bundle if the config key is set.
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
        return HandlerResolver::resolve(
            $config,
            $key,
            $interface,
            $this->manager
        );
    }
}
