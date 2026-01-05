<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Exceptions\Token\MissingHeaderAlgorithmException;
use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtHeader;

use function implode;

final class JwtHeaderFactory
{
    /**
     * Separator used when deriving a default KID from algorithm components.
     */
    private const KID_PART_SEPARATOR = '_';

    public function __construct(
        private readonly JwtKeyManager $manager,
    ) {}

    /**
     * Builds a JwtHeader and ensures the KID can be resolved.
     *
     * @throws MissingHeaderAlgorithmException
     * @throws UnresolvableKeyException
     */
    public function create(
        string $typ,
        ?string $alg,
        ?string $kid = null,
        ?string $enc = null,
    ): JwtHeader {
        if ($alg === null) {
            throw new MissingHeaderAlgorithmException('header.alg');
        }

        $resolvedKid = $this->resolveKid($kid, $alg, $enc);

        return $this->buildHeader($typ, $alg, $resolvedKid, $enc);
    }

    private function buildHeader(
        string $typ,
        string $alg,
        string $kid,
        ?string $enc,
    ): JwtHeader {
        $header = (new JwtHeader())
            ->setType($typ)
            ->setAlgorithm($alg)
            ->setKid($kid);

        if ($enc !== null && $enc !== '') {
            $header->setEnc($enc);
        }

        return $header;
    }

    private function resolveKid(
        ?string $kid,
        string $alg,
        ?string $enc,
    ): string {
        $kid ??= $this->deriveDefaultKid($alg, $enc);
        $this->assertKnownKid($kid);

        return $kid;
    }

    /**
     * Example: "RSA_OAEP_A256GCM"
     */
    private function deriveDefaultKid(
        string $alg,
        ?string $enc,
        string $separator = self::KID_PART_SEPARATOR,
    ): string {
        $parts = [];

        if ($alg !== 'dir') {
            $parts[] = $alg;
        }

        if ($enc !== null && $enc !== '') {
            $parts[] = $enc;
        }

        return implode($separator, $parts);
    }

    private function assertKnownKid(string $kid): void
    {
        if (! $this->canResolveKid($kid)) {
            throw new UnresolvableKeyException($kid);
        }
    }

    private function canResolveKid(string $kid): bool
    {
        return $this->manager->hasKey($kid)
            || $this->manager->hasPassphrase($kid);
    }
}
