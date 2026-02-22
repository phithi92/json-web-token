<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Exceptions\Token\MissingHeaderAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtTokenKind;

use function implode;

final class JwtHeaderFactory
{
    /**
     * Separator used when deriving a default KID from algorithm components.
     */
    private const KID_PART_SEPARATOR = '/';

    /**
     * Builds a JwtHeader and ensures the KID can be resolved.
     *
     * @throws MissingHeaderAlgorithmException
     * @throws UnresolvableKeyException
     */
    public function create(
        JwtTokenKind $typ,
        ?string $alg,
        ?string $kid = null,
        ?string $enc = null,
    ): JwtHeader {
        if ($alg === null) {
            throw new MissingHeaderAlgorithmException('header.alg');
        }

        $resolvedKid = $kid ?? $this->deriveDefaultKid($alg, $enc);

        return $this->buildHeader($typ, $resolvedKid, $alg, $enc);
    }

    private function buildHeader(
        JwtTokenKind $typ,
        string $kid,
        string $alg,
        ?string $enc,
    ): JwtHeader {
        $header = (new JwtHeader())
            ->setType($typ->value)
            ->setAlgorithm($alg)
            ->setKid($kid);

        if ($enc !== null && $enc !== '') {
            $header->setEnc($enc);
        }

        return $header;
    }

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
}
