<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenIssuerFactoryInterface;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\JwtIdRegistryInterface;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtTokenCreator
{
    public function __construct(
        private readonly JwtTokenIssuerFactoryInterface $issuerFactory,
        private readonly JwtPayloadCodec $payloadCodec,
        private readonly JwtValidator $defaultValidator,
    ) {
    }

    public function createToken(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $issuer = $this->issuerFactory->createIssuer($manager);

        $bundle = $issuer->issue(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );

        $validator ??= $this->defaultValidator;
        $validator->assertValidBundle($bundle);
        $this->registerJwtId($bundle, $validator);

        return $bundle;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function createTokenFromArray(
        string $algorithm,
        JwtKeyManager $manager,
        array $claims,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $payload = $this->payloadCodec->decode(claims: $claims);

        return $this->createToken(
            algorithm: $algorithm,
            manager: $manager,
            payload: $payload,
            validator: $validator,
            kid: $kid
        );
    }

    /**
     * ⚠️ No claim validation (testing only).
     */
    public function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $issuer = $this->issuerFactory->createIssuer($manager);

        return $issuer->issue(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );
    }

    public function createFromBundle(
        JwtKeyManager $manager,
        JwtBundle $bundle,
        ?string $algorithm = null,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $issuer = $this->issuerFactory->createIssuer($manager);

        $issued = $issuer->issueFromBundle(bundle: $bundle, algorithm: $algorithm);

        $validator ??= $this->defaultValidator;
        $validator->assertValidBundle($issued);
        $this->registerJwtId($issued, $validator);

        return $issued;
    }

    private function registerJwtId(JwtBundle $bundle, JwtValidator $validator): void
    {
        $jwtIdValidator = $validator->getJwtIdValidator();
        if (! $jwtIdValidator instanceof JwtIdRegistryInterface) {
            return;
        }

        $jwtId = $bundle->getPayload()->getJwtId();
        if ($jwtId === null) {
            return;
        }

        $exp = $bundle->getPayload()->getExpiration();
        if ($exp === null) {
            return;
        }

        $ttl = $exp - time();
        if ($ttl <= 0) {
            return;
        }

        $jwtIdValidator->allow($jwtId, $ttl);
    }
}
