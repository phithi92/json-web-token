<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Interfaces\CekHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\IvHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\KeyHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\PayloadHandlerInterface;
use Phithi92\JsonWebToken\Interfaces\SignatureHandlerInterface;

final class JwtTokenBuilder
{
    private const KID_PART_SEPARATOR = '_';

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
     * DO NOT USE in production: skips all validation logic.
     *
     * This method bypasses claim/context validation and should only be used for testing.
     *
     * @throws LogicException
     */
    public function createWithoutValidation(
        JwtPayload $payload,
        string $algorithm,
        ?string $kid = null
    ): EncryptedJwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        [$typ, $alg, $enc] = $this->extractHeaderParams($config);

        $header = $this->createHeader($typ, $alg, $kid, $enc);
        $bundle = new EncryptedJwtBundle($header, $payload);

        foreach (self::HANDLER_MAPPINGS as $key => [$interface, $method]) {
            $this->applyHandler($bundle, $config, $key, $interface, $method);
        }

        return $bundle;
    }

    /**
     * Extracts core header parameters from algorithm configuration.
     *
     * @param array<string, mixed> $config
     *
     * @return array{string,string|null,string|null} [$typ, $alg, $enc]
     *
     * @throws LogicException If required keys are missing
     */
    private function extractHeaderParams(array $config): array
    {
        $tokenType = $config['token_type'] ?? null;
        $alg = $config['alg'] ?? null;
        $enc = $config['enc'] ?? null;

        $this->assertResolvableHeaderConfig($tokenType, $alg, $enc);

        /** @var string $tokenType */
        /** @var string|null $alg */
        /** @var string|null $enc */

        return [$tokenType, $alg, $enc];
    }

    private function assertResolvableHeaderConfig(mixed $tokenType, mixed $alg, mixed $enc): void
    {
        if (! is_string($tokenType) || (! is_string($alg) && $alg !== null) || (! is_string($enc) && $enc !== null)) {
            throw new LogicException('Invalid header configuration');
        }
    }

    /**
     * Create header on config and params
     */
    private function createHeader(string $typ, ?string $alg, ?string $kid, ?string $enc): JwtHeader
    {
        if ($alg === null) {
            throw new InvalidFormatException('Incomplete token header configuration');
        }

        $kid ??= $this->buildDefaultKid($alg, $enc);

        $this->assertResolvableKid($kid);

        return $this->buildHeader($typ, $alg, $enc, $kid);
    }

    private function assertResolvableKid(string $kid): void
    {
        if (! $this->isResolvableKid($kid)) {
            throw new UnresolvableKeyException($kid);
        }
    }

    private function isResolvableKid(string $kid): bool
    {
        return $this->manager->hasKey($kid) || $this->manager->hasPassphrase($kid);
    }

    private function buildHeader(string $typ, string $alg, ?string $enc, string $kid): JwtHeader
    {
        $header = (new JwtHeader())->setType($typ)->setAlgorithm($alg);

        if ($enc !== null) {
            $header->setEnc($enc);
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

        return implode(self::KID_PART_SEPARATOR, $parts);
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
