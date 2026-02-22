<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service;

use DomainException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenIssuerFactoryInterface;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtTokenCreator
{
    public function __construct(
        private readonly JwtTokenIssuerFactoryInterface $issuerFactory,
        private readonly JwtPayloadCodec $payloadCodec,
        private readonly JwtValidator $defaultValidator,
    ) {
    }

    /**
     * Generates and validates a JWT with automatic JTI handling when validation is enabled.
     *
     * @param non-empty-string $algorithm
     * @param JwtKeyManager $manager
     * @param JwtPayload|null $payload
     * @param JwtValidator|null $validator Default validator used if null
     * @param string|null $kid Key identifier
     *
     * @return JwtBundle Validated JWT bundle
     */
    public function createToken(
        string $algorithm,
        JwtKeyManager $manager,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $issuer = $this->issuerFactory->createIssuer($manager);
        $validator ??= $this->defaultValidator;

        if ($validator->getJwtIdValidator() !== null && $payload?->getJwtId() === null) {
            if ($payload?->getExpiration() === null) {
                throw new DomainException('JWT payload requires expiration claim (exp) when JTI validation is enabled');
            }
            $jwtId = new JwtIdInput();
            $validator->getJwtIdValidator()->allow($jwtId, (int) $payload->getExpiration());
            $payload->setJwtId($jwtId);
        }

        $bundle = $issuer->issue(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );

        $validator->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Generates and validates a JWT from an array of claims.
     *
     * @param non-empty-string $algorithm
     * @param JwtKeyManager $manager
     * @param array<non-empty-string, mixed> $claims JWT claims as key-value pairs
     * @param JwtValidator|null $validator Default validator used if null
     * @param string|null $kid Key identifier
     *
     * @return JwtBundle Validated JWT bundle
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

    /**
     * Re-issues and validates an existing JWT bundle with optional algorithm override.
     *
     * Handles automatic JTI generation when validation is enabled and the original bundle
     * lacks a JWT ID but contains an expiration claim.
     *
     * @param JwtKeyManager $manager Key management instance
     * @param JwtBundle $bundle Original JWT bundle to re-issue
     * @param non-empty-string|null $algorithm Optional algorithm override (uses bundle's algorithm if null)
     * @param JwtValidator|null $validator Optional validator (uses default if null)
     *
     * @return JwtBundle New validated JWT bundle
     */
    public function createFromBundle(
        JwtKeyManager $manager,
        JwtBundle $bundle,
        ?string $algorithm = null,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $issuer = $this->issuerFactory->createIssuer($manager);
        $validator ??= $this->defaultValidator;

        if ($validator->getJwtIdValidator() !== null && $bundle->getPayload()->getJwtId() === null) {
            if ($bundle->getPayload()->getExpiration() === null) {
                throw new DomainException('JWT payload requires expiration claim (exp) when JTI validation is enabled');
            }
            $jwtId = new JwtIdInput();
            $validator->getJwtIdValidator()->allow($jwtId, (int) $bundle->getPayload()->getExpiration());
            $bundle->getPayload()->setJwtId($jwtId);
        }

        $issued = $issuer->issueFromBundle(bundle: $bundle, algorithm: $algorithm);

        $validator->assertValidBundle($issued);

        return $issued;
    }
}
