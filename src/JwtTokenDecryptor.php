<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Core\HandlerResolver;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

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
            'key_management' => [KeyHandlerInterface::class, 'unwrapKey'],
            'cek' => [CekHandlerInterface::class, 'validateCek'],
            'iv' => [IvHandlerInterface::class, 'validateIv'],
            'signing_algorithm' => [SignatureHandlerInterface::class, 'validateSignature'],
            'content_encryption' => [PayloadHandlerInterface::class, 'decryptPayload'],
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
