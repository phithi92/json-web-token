<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Handler\Processor\AbstractJwtTokenProcessor;

final class JwtTokenBuilder extends AbstractJwtTokenProcessor
{
    public const OPERATION = HandlerOperation::Perform;
    private const string KID_PART_SEPARATOR = '_';

    public function __construct(
        JwtAlgorithmManager $manager
    ) {
        parent::__construct($manager);
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

        $this->dispatchHandlers($bundle, $algorithm, self::OPERATION);

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
}
