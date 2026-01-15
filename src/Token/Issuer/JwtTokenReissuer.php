<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Issuer;

namespace Phithi92\JsonWebToken\Token\Issuer;

/**
 * Description of JwtTokenReissuer
 *
 * @author phillipthiele
 */
final class JwtTokenReissuer
{
    public function __construct(
        private readonly JwtTokenCreator $creator,
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

        $payload = $this->buildFilteredPayload(bundle: $bundle)
            ->setExpiration(interval: $interval);

        $newBundle = new JwtBundle(header: $bundle->getHeader(), payload: $payload);

        // Decide policy: reissue always validates the new bundle by default.
        $validator->assertValidBundle(bundle: $newBundle);

        // Re-sign/re-encrypt from bundle using the issuer underneath.
        // If your JwtTokenIssuer has createFromBundle(), keep using it.
        // Otherwise you could call createToken() with header/payload separately.
        // Here we assume createFromBundle exists like in your current codebase.
        $issuer = ($this->creator) // get issuer via factory in creator
        ; // placeholder to show intent

        // We don't have direct access to issuer from creator, so we call issuer through factory:
        // easiest: add a method in creator to "createFromBundle", or re-inject issuerFactory here.
        // We'll do the clean thing: call a dedicated method on creator.

        return $this->createFromBundle($newBundle, $manager);
    }

    private function createFromBundle(JwtBundle $bundle, JwtKeyManager $manager): JwtBundle
    {
        $issuerFactoryProperty = $this->issuerFactory->createIssuer($manager);

        /** @var JwtTokenIssuerFactoryInterface $issuerFactory */
        $issuerFactory = $issuerFactoryProperty->getValue($this->creator);

        $issuer = $issuerFactory->createIssuer($manager);

        return $issuer->createFromBundle(bundle: $bundle);
    }

    private function buildFilteredPayload(JwtBundle $bundle): JwtPayload
    {
        $referencePayload = $bundle->getPayload();

        /** @var array<string, mixed> $filteredClaims */
        $filteredClaims = $this->filterClaims(payload: $referencePayload);

        return $this->payloadCodec->decode(claims: $filteredClaims);
    }

    /** @return array<string, mixed> */
    private function filterClaims(JwtPayload $payload): array
    {
        $claims = $payload->toArray();

        foreach (DateClaimHelper::TIME_CLAIMS as $key) {
            unset($claims[$key]);
        }

        return $claims;
    }
}
