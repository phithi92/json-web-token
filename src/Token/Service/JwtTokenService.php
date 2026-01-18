<?php


declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtTokenService
{
    public function __construct(
        private readonly JwtTokenCreator $creator,
        private readonly JwtTokenReader $reader,
        private readonly JwtClaimsValidationService $claimsValidator,
        private readonly JwtTokenReissuer $reissuer,
    ) {
    }

    public function createToken(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->creator->createToken($algorithm, $manager, $payload, $validator, $kid);
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
        return $this->creator->createTokenFromArray($algorithm, $manager, $claims, $validator, $kid);
    }

    public function createTokenWithoutClaimValidation(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->creator->createTokenWithoutClaimValidation($algorithm, $manager, $payload, $kid);
    }

    public function createTokenString(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): string {
        $bundle = $this->createToken($algorithm, $manager, $payload, $validator, $kid);

        return JwtBundleCodec::serialize($bundle);
    }

    public function decryptToken(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reader->decryptToken($token, $manager, $validator);
    }

    public function decryptTokenWithoutClaimValidation(
        string $token,
        JwtKeyManager $manager,
    ): JwtBundle {
        return $this->reader->decryptTokenWithoutClaimValidation($token, $manager);
    }

    public function validateTokenClaims(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): bool {
        return $this->claimsValidator->validateTokenClaims($token, $manager, $validator);
    }

    public function reissueBundleFromToken(
        string $token,
        string $interval,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reissuer->reissueBundleFromToken($token, $interval, $manager, $validator);
    }

    public function reissueBundle(
        string $interval,
        JwtBundle $bundle,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        return $this->reissuer->reissueBundle($interval, $bundle, $manager, $validator);
    }

    public function denyJwtId(string $jwtId, int $ttl, JwtValidator $validator): void
    {
        $jwtIdValidator = $validator->getJwtIdValidator();
        if (! $jwtIdValidator instanceof JwtIdRegistryInterface) {
            return;
        }

        if ($ttl <= 0) {
            return;
        }

        $jwtIdValidator->deny($jwtId, $ttl);
    }

    public function denyBundle(JwtBundle $bundle, JwtValidator $validator): void
    {
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

        $this->denyJwtId($jwtId, $ttl, $validator);
    }
}
