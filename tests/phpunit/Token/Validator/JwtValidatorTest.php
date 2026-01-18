<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Validator;

use Phithi92\JsonWebToken\Exceptions\Payload\ExpiredPayloadException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidAudienceException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuedAtException;
use Phithi92\JsonWebToken\Exceptions\Payload\InvalidIssuerException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotBeforeOlderThanIatException;
use Phithi92\JsonWebToken\Exceptions\Payload\NotYetValidException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidJwtIdException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidPrivateClaimException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingPrivateClaimException;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use PHPUnit\Framework\TestCase;

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

        if (isset($data['jti'])) {
            $payload->setJwtId($data['jti']);
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
                'jti' => 'token-123',
                'customClaim' => 'abc',
            ]
        );

        $validator = new JwtValidator(
            'trusted-issuer',
            'my-app',
            2,
            ['customClaim' => 'abc'],
            // allow-list aktiv (useAllowList = true), token-123 ist erlaubt
            new InMemoryJwtIdValidator(['token-123'], null, true)
        );

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

    public function testIsValidReturnsFalseForExpiredToken(): void
    {
        $payload = $this->createPayload(['exp' => '-1 hour']);
        $validator = new JwtValidator();

        $this->assertFalse($validator->isValid($payload));
    }

    public function testNotYetValidTokenThrowsException(): void
    {
        $payload = $this->createPayload(
            [
                'nbf' => '+1 minutes',
                'iat' => 'now',
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
                'iat' => 'now',
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

    public function testIsValidReturnsFalseForInvalidIssuer(): void
    {
        $payload = $this->createPayload(['iss' => 'wrong']);
        $validator = new JwtValidator('correct');

        $this->assertFalse($validator->isValid($payload));
    }

    public function testInvalidAudienceThrowsException(): void
    {
        $payload = $this->createPayload(['aud' => 'not-matching']);
        $validator = new JwtValidator(null, 'expected');

        $this->expectException(InvalidAudienceException::class);
        $validator->assertValid($payload);
    }

    public function testInvalidJwtIdThrowsException(): void
    {
        $payload = $this->createPayload(['jti' => 'token-1']);
        $validator = new JwtValidator(
            expectedIssuer: null,
            expectedAudience: null,
            clockSkew: 0,
            expectedClaims: [],
            // allow-list aktiv, token-1 ist NICHT erlaubt -> Exception
            jwtIdValidator: new InMemoryJwtIdValidator(['token-2'], null, true)
        );

        $this->expectException(InvalidJwtIdException::class);
        $validator->assertValid($payload);
    }

    public function testIsValidReturnsFalseForInvalidJwtId(): void
    {
        $payload = $this->createPayload(['jti' => 'token-1']);
        $validator = new JwtValidator(
            expectedIssuer: null,
            expectedAudience: null,
            clockSkew: 0,
            expectedClaims: [],
            // allow-list aktiv, token-1 ist NICHT erlaubt -> isValid false
            jwtIdValidator: new InMemoryJwtIdValidator(['token-2'], null, true)
        );

        $this->assertFalse($validator->isValid($payload));
    }

    public function testJwtIdAllowListRejectsMissingJwtId(): void
    {
        $payload = $this->createPayload([]);
        $validator = new JwtValidator(
            expectedIssuer: null,
            expectedAudience: null,
            clockSkew: 0,
            expectedClaims: [],
            // allow-list aktiv -> fehlende jti ist NICHT erlaubt
            jwtIdValidator: new InMemoryJwtIdValidator(['token-1'], null, true)
        );

        $this->expectException(InvalidJwtIdException::class);
        $validator->assertValid($payload);
    }

    public function testJwtIdDenyListAllowsMissingJwtIdWhenAllowListDisabled(): void
    {
        $payload = $this->createPayload([]);
        $validator = new JwtValidator(
            expectedIssuer: null,
            expectedAudience: null,
            clockSkew: 0,
            expectedClaims: [],
            // allow-list aus -> fehlende jti ist erlaubt (sofern nicht explizit required)
            jwtIdValidator: new InMemoryJwtIdValidator(null, ['token-1'], false)
        );

        $validator->assertValid($payload);
        $this->assertTrue($validator->isValid($payload));
    }

    public function testJwtIdDenyListRejectsKnownJwtId(): void
    {
        $payload = $this->createPayload(['jti' => 'token-1']);
        $validator = new JwtValidator(
            expectedIssuer: null,
            expectedAudience: null,
            clockSkew: 0,
            expectedClaims: [],
            // deny-list aktiv, allow-list aus -> token-1 abgelehnt
            jwtIdValidator: new InMemoryJwtIdValidator(null, ['token-1'], false)
        );

        $this->expectException(InvalidJwtIdException::class);
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

    public function testPrivateClaimPresenceWithoutSpecificValueIsAccepted(): void
    {
        $payload = $this->createPayload(['role' => 'guest']);
        $validator = new JwtValidator(null, null, 0, ['role' => null]);

        $validator->assertValid($payload);
        $this->assertTrue($validator->isValid($payload));
    }
}
