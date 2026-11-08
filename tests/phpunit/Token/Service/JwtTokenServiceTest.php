<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Service;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingJwtIdException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtIdValidatorInterface;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

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

        $service = new JwtTokenService($validator);

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

    public function testDenyBundleThrowExceptionWithoutJwtId(): void
    {
        $registry = $this->createMock(JwtIdValidatorInterface::class);
        $registry->expects($this->never())->method('deny');

        $validator = new JwtValidator(jwtIdValidator: $registry);

        $service = new JwtTokenService($validator);

        $payload = (new JwtPayload())->setClaimTimestamp('exp', time() + 600);
        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'), $payload);

        $this->expectException(MissingJwtIdException::class);
        $service->denyBundle($bundle, $validator);

        $this->expectException(LogicException::class);
        $service->denyJwtId(123, time() + 2);
    }

    public function testThrowExceptionWithoutJwtIdValidator(): void
    {
        $validator = new JwtValidator();

        $service = new JwtTokenService($validator);

        $payload = (new JwtPayload())
            ->setJwtId(new JwtIdInput('token-id'))
            ->setClaimTimestamp('exp', time() + 600);

        $bundle = new JwtBundle((new JwtHeader())->setAlgorithm('HS256'), $payload);

        $this->expectException(RuntimeException::class);
        $service->denyJwtId('token-id', time() + 2, new JwtValidator());
    }
}
