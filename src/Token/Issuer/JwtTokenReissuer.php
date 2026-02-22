<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Issuer;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenIssuerFactory;
use Phithi92\JsonWebToken\Token\Helper\DateClaimHelper;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

/**
 * Description of JwtTokenReissuer
 *
 * @author phillipthiele
 */
final class JwtTokenReissuer
{
    public function __construct(
        private readonly JwtPayloadCodec $payloadCodec,
        private readonly JwtValidator $defaultValidator,
        private readonly JwtTokenIssuerFactory $issuerFactory,
    ) {
    }

    public function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reissueBundle(
            interval: $interval,
            bundle: JwtBundleCodec::parse($token),
            manager: $manager,
            validator: $validator
        );
    }

    public function reissueBundle(
        string $interval,
        JwtBundle $bundle,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $validator ??= $this->defaultValidator;

        $filterdPayload = $this->filterPayload($bundle);

        $filterdPayload->setExpiration($interval);

        $reissuedBundle = new JwtBundle(
            header: $bundle->getHeader(),
            payload: $filterdPayload,
            encryption: $bundle->hasEncryption() ? $bundle->getEncryption() : null,
        );

        // Decide policy: reissue always validates the new bundle by default.
        $validator->assertValidBundle($reissuedBundle);

        return $this->createFromBundle($reissuedBundle, $manager);
    }

    private function createFromBundle(JwtBundle $bundle, JwtKeyManager $manager): JwtBundle
    {
        $issuerFactory = $this->issuerFactory->createIssuer($manager);

        return $issuerFactory->issueFromBundle($bundle);
    }

    private function filterPayload(JwtBundle $bundle): JwtPayload
    {
        $referencePayload = $bundle->getPayload();

        $filteredClaims = $this->filterClaims(payload: $referencePayload);

        return $this->payloadCodec->decode(claims: $filteredClaims);
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
