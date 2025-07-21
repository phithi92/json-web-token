<?php

declare(strict_types=1);

namespace Tests\phpunit;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtValidator;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotYetValidException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuerException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidAudienceException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuedAtException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotBeforeOlderThanIatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidPrivateClaimException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingPrivateClaimException;

final class JwtValidatorTest extends TestCase
{
    private function createPayloadMock(array $data): JwtPayload
    {
        $mock = $this->createMock(JwtPayload::class);

        $mock->method('getExpiration')->willReturn($data['exp'] ?? null);
        $mock->method('getNotBefore')->willReturn($data['nbf'] ?? null);
        $mock->method('getIssuedAt')->willReturn($data['iat'] ?? null);
        $mock->method('getIssuer')->willReturn($data['iss'] ?? null);
        $mock->method('getAudience')->willReturn($data['aud'] ?? null);
        $mock->method('getClaim')->willReturnCallback(fn($key) => $data[$key] ?? null);
        $mock->method('hasClaim')->willReturnCallback(fn($key) => isset($data[$key]));
        $mock->method('toArray')->willReturnCallback(fn() => $data ?? null);

        return $mock;
    }

    public function testValidPayload(): void
    {
        $now = time();
        $payload = $this->createPayloadMock(
            [
            'exp' => $now + 3600,
            'nbf' => $now - 60,
            'iat' => $now - 120,
            'iss' => 'trusted-issuer',
            'aud' => 'my-app',
            'customClaim' => 'abc'
            ]
        );

        $validator = new JwtValidator('trusted-issuer', 'my-app', 30, ['customClaim' => 'abc']);
        $this->assertTrue($validator->isValid($payload));
    }

    public function testExpiredTokenThrowsException(): void
    {
        $payload = $this->createPayloadMock(['exp' => time() - 3600]);
        $validator = new JwtValidator();

        $this->expectException(ExpiredPayloadException::class);
        $validator->assertValid($payload);
    }

    public function testNotYetValidTokenThrowsException(): void
    {
        $now = time();
        $payload = $this->createPayloadMock(
            [
            'nbf' => $now + 60,
            'iat' => $now
            ]
        );

        $validator = new JwtValidator();
        $this->expectException(NotYetValidException::class);
        $validator->assertValid($payload);
    }

    public function testIatInFutureThrowsException(): void
    {
        $payload = $this->createPayloadMock(['iat' => time() + 300]);
        $validator = new JwtValidator();

        $this->expectException(InvalidIssuedAtException::class);
        $validator->assertValid($payload);
    }

    public function testNbfBeforeIatThrowsException(): void
    {
        $now = time();
        $payload = $this->createPayloadMock(
            [
            'nbf' => $now - 60,
            'iat' => $now
            ]
        );

        $validator = new JwtValidator();
        $this->expectException(NotBeforeOlderThanIatException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidIssuerThrowsException(): void
    {
        $payload = $this->createPayloadMock(['iss' => 'wrong']);
        $validator = new JwtValidator('correct');

        $this->expectException(InvalidIssuerException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidAudienceThrowsException(): void
    {
        $payload = $this->createPayloadMock(['aud' => 'not-matching']);
        $validator = new JwtValidator(null, 'expected');

        $this->expectException(InvalidAudienceException::class);
        $validator->assertValid($payload);
    }

    public function testMissingPrivateClaimThrowsException(): void
    {
        $payload = $this->createPayloadMock([]);
        $validator = new JwtValidator(null, null, 0, ['custom' => null]);

        $this->expectException(MissingPrivateClaimException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidPrivateClaimValueThrowsException(): void
    {
        $payload = $this->createPayloadMock(['role' => 'user']);
        $validator = new JwtValidator(null, null, 0, ['role' => 'admin']);

        $this->expectException(InvalidPrivateClaimException::class);
        $validator->assertValid($payload);
    }

    public function testPrivateClaimSetToEmptyStringShouldNotPassWhenValueExpected(): void
    {
        $payload = $this->createPayloadMock(['role' => '']);
        $validator = new JwtValidator(null, null, 0, ['role' => 'admin']);

        $this->expectException(InvalidPrivateClaimException::class);
        $validator->assertValid($payload);
    }
}
