<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Issuer;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;

final class JwtTokenReissuer
{
    public function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
    ): JwtBundle {
        $bundle = JwtBundleCodec::parse($token);

        return $this->reissueBundle(
            interval: $interval,
            bundle: $bundle,
            manager: $manager
        );
    }

    public function reissueBundle(
        string $interval,
        JwtBundle $bundle,
        JwtKeyManager $manager
    ): JwtBundle {
        $payload = $this->buildPayloadFromBundle($bundle);
        $payload->setExpiration($interval);

        $reissuedBundle = new JwtBundle(
            header: $bundle->getHeader(),
            payload: $payload,
            encryption: $bundle->hasEncryption() ? $bundle->getEncryption() : null,
        );

        $issuer = new JwtTokenIssuer($manager);

        return $issuer->issueFromBundle($reissuedBundle);
    }

    private function buildPayloadFromBundle(JwtBundle $bundle): JwtPayload
    {
        $referencePayload = $bundle->getPayload();

        $filteredClaims = $this->filterClaims($referencePayload);

        return JwtPayloadCodec::decode($filteredClaims);
    }

    /** @return array<string, mixed> */
    private function filterClaims(JwtPayload $payload): array
    {
        $claims = $payload->toArray();

        $searchFor = DateClaimHelper::TIME_CLAIMS + [
            'jti' => true,
        ];

        foreach ($searchFor as $key => $value) {
            unset($claims[$key]);
        }

        return $claims;
    }
}
