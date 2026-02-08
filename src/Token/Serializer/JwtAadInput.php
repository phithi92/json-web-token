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
    /**
     * Encodes Additional Authenticated Data (AAD) depending on token type.
     */
    public function encode(JwtBundle $bundle): string
    {
        $kind = JwtTokenKind::fromTypeOrFail($bundle->getHeader()->getType());

        return match ($kind) {
            JwtTokenKind::JWE => $this->encodeJweAad($bundle),
            JwtTokenKind::JWS,
            JwtTokenKind::JWT => $this->encodeJwsAad($bundle)
        };
    }

    private function encodeJweAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());

        return Base64UrlEncoder::encode($jsonHeader);
    }

    private function encodeJwsAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        $jsonPayload = JwtPayloadJsonCodec::encodeStatic($bundle->getPayload());

        return Base64UrlEncoder::encode($jsonHeader) . '.'
            . Base64UrlEncoder::encode($jsonPayload);
    }
}
