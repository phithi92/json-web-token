<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Serializer;

use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtTokenKind;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

final class JwtAadInput
{
    private readonly string $encoded;

    public function __construct(JwtBundle $bundle)
    {
        $this->encoded = $this->computeAad($bundle);
    }

    public function getEncoded(): string
    {
        return $this->encoded;
    }

    // Optional: Factory-Methode für bessere Lesbarkeit
    public static function fromBundle(JwtBundle $bundle): self
    {
        return new self($bundle);
    }

    private function computeAad(JwtBundle $bundle): string
    {
        $kind = JwtTokenKind::fromTypeOrFail($bundle->getHeader()->getType());

        return match ($kind) {
            JwtTokenKind::JWE => $this->computeJweAad($bundle),
            JwtTokenKind::JWS,
            JwtTokenKind::JWT => $this->computeJwsAad($bundle)
        };
    }

    private function computeJweAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        return Base64UrlEncoder::encode($jsonHeader);
    }

    private function computeJwsAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        $jsonPayload = JwtPayloadJsonCodec::encodeStatic($bundle->getPayload());

        return Base64UrlEncoder::encode($jsonHeader) . '.'
            . Base64UrlEncoder::encode($jsonPayload);
    }
}
