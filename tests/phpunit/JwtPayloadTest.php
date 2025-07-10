<?php

declare(strict_types=1);

namespace Tests;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\Exceptions;
use Phithi92\JsonWebToken\JwtValidator;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use DateTime;

/**
 * Description of JwtPayloadTest
 *
 * @author phillip
 */
class JwtPayloadTest extends TestCase
{
    public function testAddField()
    {
        $payload = new JwtPayload();
        $payload->addClaim('custom', 'testValue');

        $this->assertEquals('testValue', $payload->getClaim('custom'));
    }

    public function testSetIssuer()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer');

        $this->assertEquals('testIssuer', $payload->getClaim('iss'));
    }

    public function testSetAudience()
    {
        $payload = new JwtPayload();
        $payload->setAudience(['aud1', 'aud2']);

        $this->assertEquals(['aud1', 'aud2'], $payload->getClaim('aud'));
    }

    public function testSetIssuedAt()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-01-01T00:00:00Z';
        $payload->setIssuedAt($dateTime);

        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getClaim('iat'));
    }

    public function testSetExpiration()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-12-31T23:59:59Z';
        $payload->setExpiration($dateTime);

        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getClaim('exp'));
    }

    public function testSetNotBefore()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-06-01T12:00:00Z';
        $payload->setNotBefore($dateTime);

        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getClaim('nbf'));
    }


    public function testToArray()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')->setAudience('testAudience');
        $payload->setExpiration('+15 minutes');

        $array = $payload->toArray();
        $this->assertArrayHasKey('iss', $array);
        $this->assertEquals('testIssuer', $array['iss']);
        $this->assertEquals('testAudience', $array['aud']);
    }

    public function testToJson()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')->setAudience('testAudience');
        $payload->setExpiration('+15 minutes');

        $json = $payload->toJson();
        $decoded = json_decode($json, true);

        $this->assertArrayHasKey('iss', $decoded);
        $this->assertEquals('testIssuer', $decoded['iss']);
        $this->assertEquals('testAudience', $decoded['aud']);
    }

    public function testToArrayIncludesAllFields()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')
                ->setAudience(['aud1', 'aud2'])
                ->setExpiration('+15 minutes')
                ->setIssuedAt('now')
                ->setNotBefore('now');

        $array = $payload->toArray();
        $this->assertArrayHasKey('iss', $array);
        $this->assertArrayHasKey('aud', $array);
        $this->assertArrayHasKey('exp', $array);
        $this->assertArrayHasKey('iat', $array);
        $this->assertArrayHasKey('nbf', $array);
    }

    public function testToJsonIncludesAllFields()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')
                ->setAudience(['aud1', 'aud2'])
                ->setExpiration('+15 minutes')
                ->setIssuedAt('now')
                ->setNotBefore('now');

        $json = $payload->toJson();
        $decoded = json_decode($json, true);

        $this->assertArrayHasKey('iss', $decoded);
        $this->assertArrayHasKey('aud', $decoded);
        $this->assertArrayHasKey('exp', $decoded);
        $this->assertArrayHasKey('iat', $decoded);
        $this->assertArrayHasKey('nbf', $decoded);
    }

    public function testAudienceArrayWithSingleExpectedMatch()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $payload->setAudience(['aud1', 'aud2', 'aud3']);

        // Should pass because at least one audience matches
        $validator = new JwtValidator(null, 'aud3');
        $validator->isValidAudience($payload);
    }

    public function testValidateTokenExpirationInFutureSucceeds()
    {
        $this->expectNotToPerformAssertions();

        $payload = (new JwtPayload())
                ->setIssuedAt('now')
                ->setExpiration('+1 minutes');

        // This should succeed because the `exp` is set in the future
        $validator = new JwtValidator();
        $validator->assertValid($payload);
    }

    public function testValidateTokenExpiredThrowsException()
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-2 minutes')
                ->setExpiration('-1 minutes');

        $this->expectException(Exceptions\Payload\ExpiredPayloadException::class);

        // This should throw an exception because the `exp` is set in the past
        $validator = new JwtValidator();
        $validator->assertValid($payload);
    }

    public function testValidateTokenAllTemporalClaimsValid()
    {
        $this->expectNotToPerformAssertions();

        $payload = (new JwtPayload())
                ->setIssuedAt('-1 minutes')
                ->setNotBefore('-1 minutes')
                ->setExpiration('+1 minutes');

        // This should succeed because all temporal claims are valid
        $validator = new JwtValidator();
        $validator->assertValid($payload);
    }

    public function testValidateTokenWithMixedInvalidTemporalClaims()
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-2 minutes')
                ->setNotBefore('-2 minutes')
                ->setExpiration('-1 minutes');

        $this->expectException(Exceptions\Payload\ExpiredPayloadException::class);

        // This should throw an `Expired` exception because `exp` is in the past
        $validator = new JwtValidator();
        $validator->assertValid($payload);
    }

    public function testSetExpirationWithUnixMaxTime()
    {
        $dateTime = new DateTimeImmutable('@2147483647'); // Maximale 32-bit Zeit

        $payload = (new JwtPayload())
                ->setExpiration($dateTime->format(DateTime::ATOM));

        $this->assertEquals($dateTime->getTimestamp(), $payload->getClaim('exp'));
    }

    public function testSetNotBeforeWithInvalidDateThrowsException()
    {
        $this->expectException(Exceptions\Payload\InvalidDateTimeException::class);

        (new JwtPayload())
                ->setNotBefore('invalid-date-format');
    }
}
