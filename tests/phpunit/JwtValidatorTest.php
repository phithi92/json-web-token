<?php

declare(strict_types=1);

namespace Tests\phpunit;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Token\JwtPayload;
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
    private function createPayload(array $data): JwtPayload
    {
        $payload = new JwtPayload();

        if (isset($data['exp'])) {
            $payload->setExpiration($data['exp']);
        }

        if (isset($data['nbf'])) {
            $payload->setNotBefore($data['nbf']);
        }

        if (isset($data['iat'])) {
            $payload->setIssuedAt($data['iat']);
        }

        if (isset($data['iss'])) {
            $payload->setIssuer($data['iss']);
        }

        if (isset($data['aud'])) {
            $payload->setAudience($data['aud']);
        }

        if (isset($data['customClaim'])) {
            $payload->addClaim('customClaim', $data['customClaim']);
        }

        if (isset($data['role'])) {
            $payload->addClaim('role', $data['role']);
        }

        return $payload;
    }

    public function testValidPayload(): void
    {
        $payload = $this->createPayload(
            [
            'exp' => '+1 hour',
            'nbf' => '+1 second',
            'iat' => 'now',
            'iss' => 'trusted-issuer',
            'aud' => 'my-app',
            'customClaim' => 'abc'
            ]
        );

        $validator = new JwtValidator('trusted-issuer', 'my-app', 2, ['customClaim' => 'abc']);

        $validator->assertValid($payload);

        $this->assertTrue($validator->isValid($payload));
    }

    public function testExpiredTokenThrowsException(): void
    {
        $payload = $this->createPayload(['exp' => '-1 hour']);
        $validator = new JwtValidator();

        $this->expectException(ExpiredPayloadException::class);
        $validator->assertValid($payload);
    }

    public function testNotYetValidTokenThrowsException(): void
    {
        $payload = $this->createPayload(
            [
            'nbf' => '+1 minutes',
            'iat' => 'now'
            ]
        );

        $validator = new JwtValidator();
        $this->expectException(NotYetValidException::class);
        $validator->assertValid($payload);
    }

    public function testIatInFutureThrowsException(): void
    {
        $payload = $this->createPayload(['iat' => '+30 minutes']);
        $validator = new JwtValidator();

        $this->expectException(InvalidIssuedAtException::class);
        $validator->assertValid($payload);
    }

    public function testNbfBeforeIatThrowsException(): void
    {
        $payload = $this->createPayload(
            [
            'nbf' => '-1 minutes',
            'iat' => 'now'
            ]
        );

        $validator = new JwtValidator();
        $this->expectException(NotBeforeOlderThanIatException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidIssuerThrowsException(): void
    {
        $payload = $this->createPayload(['iss' => 'wrong']);
        $validator = new JwtValidator('correct');

        $this->expectException(InvalidIssuerException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidAudienceThrowsException(): void
    {
        $payload = $this->createPayload(['aud' => 'not-matching']);
        $validator = new JwtValidator(null, 'expected');

        $this->expectException(InvalidAudienceException::class);
        $validator->assertValid($payload);
    }

    public function testMissingPrivateClaimThrowsException(): void
    {
        $payload = $this->createPayload([]);
        $validator = new JwtValidator(null, null, 0, ['role' => null]);

        $this->expectException(MissingPrivateClaimException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidPrivateClaimValueThrowsException(): void
    {
        $payload = $this->createPayload(['role' => 'user']);
        $validator = new JwtValidator(null, null, 0, ['role' => 'admin']);

        $this->expectException(InvalidPrivateClaimException::class);
        $validator->assertValid($payload);
    }

    public function testPrivateClaimSetToEmptyStringShouldNotPassWhenValueExpected(): void
    {
        $payload = $this->createPayload(['role' => 'user']);
        $validator = new JwtValidator(null, null, 0, ['role' => 'admin']);

        $this->expectException(InvalidPrivateClaimException::class);
        $validator->assertValid($payload);
    }
}
