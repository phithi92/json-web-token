<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Service;

use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenDecryptorFactory;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenIssuerFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Service\JwtClaimsValidationService;
use Phithi92\JsonWebToken\Token\Service\JwtTokenCreator;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtIdValidatorInterface;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PHPUnit\Framework\TestCase;

final class JwtTokenServiceTest extends TestCase
{
    public function testDenyBundleRegistersJwtIdWithTtl(): void
    {
        $registry = $this->createMock(JwtIdValidatorInterface::class);
        $registry->expects($this->once())
            ->method('deny')
            ->with(
                new JwtIdInput('token-id'),
                $this->callback(static fn (int $ttl): bool => $ttl > 0)
            );

        // Wichtig: Validator mit Registry erstellen
        $validator = new JwtValidator(jwtIdValidator: $registry);

        // Wichtig: denselben Validator in alle Abhängigkeiten injizieren,
        // damit der Service (egal welchen Pfad er nutzt) den Mock verwendet.
        $creator = new JwtTokenCreator(
            new JwtTokenIssuerFactory(),
            new JwtPayloadCodec(),
            $validator
        );

        $reader = new JwtTokenReader(new JwtTokenDecryptorFactory());

        $claimsValidation = new JwtClaimsValidationService(
            $reader,
            $validator
        );

        $reissuer = new JwtTokenReissuer(
            new JwtPayloadCodec(),
            $validator,
            new JwtTokenIssuerFactory()
        );

        $service = new JwtTokenService(
            $creator,
            $reader,
            $claimsValidation,
            $reissuer
        );

        $now = time();
        $payload = (new JwtPayload())
            ->setJwtId(new JwtIdInput('token-id'))
            ->setClaimTimestamp('exp', $now + 600);

        $bundle = new JwtBundle(
            (new JwtHeader())->setAlgorithm('HS256'),
            $payload
        );

        $service->denyBundle($bundle, $validator);
    }

    public function testDenyBundleSkipsWithoutJwtId(): void
    {
        $registry = $this->createMock(JwtIdValidatorInterface::class);
        $registry->expects($this->never())->method('deny');

        $validator = new JwtValidator(jwtIdValidator: $registry);

        $service = new JwtTokenService(
            new JwtTokenCreator(new JwtTokenIssuerFactory(), new JwtPayloadCodec(), new JwtValidator()),
            new JwtTokenReader(new JwtTokenDecryptorFactory()),
            new JwtClaimsValidationService(
                new JwtTokenReader(new JwtTokenDecryptorFactory()),
                new JwtValidator()
            ),
            new JwtTokenReissuer(new JwtPayloadCodec(), new JwtValidator(), new JwtTokenIssuerFactory())
        );

        $payload = (new JwtPayload())->setClaimTimestamp('exp', time() + 600);
        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'), $payload);

        $service->denyBundle($bundle, $validator);
    }
}
