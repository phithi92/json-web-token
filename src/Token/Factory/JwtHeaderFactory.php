<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Exceptions\Token\MissingHeaderAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtTokenKind;

final class JwtHeaderFactory
{
    private const KID_PART_SEPARATOR = '/';
    private const ALG_DIRECT_KEY    = 'dir';

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

        $header = new JwtHeader();
        $header->setType($typ->value);
        $header->setAlgorithm($alg);
        $header->setKid($resolvedKid);

        if ($enc !== null && $enc !== '') {
            $header->setEnc($enc);
        }

        return $header;
    }

    /**
     * Derives a default KID from algorithm and optional encryption components.
     *
     * For a maximum of two parts, direct string concatenation avoids
     * the overhead of array allocation and implode().
     */
    private function deriveDefaultKid(string $alg, ?string $enc): string
    {
        $hasEnc = $enc !== null && $enc !== '';

        if ($alg === self::ALG_DIRECT_KEY) {
            return $hasEnc ? $enc : '';
        }

        return $hasEnc
            ? $alg . self::KID_PART_SEPARATOR . $enc
            : $alg;
    }
}
