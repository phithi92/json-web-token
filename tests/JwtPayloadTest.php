<?php

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Scripting/PHPClass.php to edit this template
 */

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use DateTimeImmutable;
use DateTime;

/**
 * Description of JwtPayloadTest
 *
 * @author phillip
 */
use PHPUnit\Framework\TestCase;

class JwtPayloadTest extends TestCase
{
    public function testAddField()
    {
        $payload = new JwtPayload();
        $payload->addField('custom', 'testValue');
        
        $this->assertEquals('testValue', $payload->getField('custom'));
    }

    public function testSetIssuer()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer');
        
        $this->assertEquals('testIssuer', $payload->getField('iss'));
    }

    public function testSetAudience()
    {
        $payload = new JwtPayload();
        $payload->setAudience(['aud1', 'aud2']);
        
        $this->assertEquals(['aud1', 'aud2'], $payload->getField('aud'));
    }

    public function testSetIssuedAt()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-01-01T00:00:00Z';
        $payload->setIssuedAt($dateTime);
        
        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getField('iat'));
    }

    public function testSetExpiration()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-12-31T23:59:59Z';
        $payload->setExpiration($dateTime);
        
        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getField('exp'));
    }

    public function testSetNotBefore()
    {
        $payload = new JwtPayload();
        $dateTime = '2024-06-01T12:00:00Z';
        $payload->setNotBefore($dateTime);
        
        $expectedTimestamp = (new DateTimeImmutable($dateTime))->getTimestamp();
        $this->assertEquals($expectedTimestamp, $payload->getField('nbf'));
    }

    public function testValidateThrowsExceptionIfExpirationMissing()
    {
        $this->expectException(Exception\Payload\MissingData::class);
        
        $payload = new JwtPayload();
        $payload->validate();
    }

    public function testValidateTemporalClaims()
    {        
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $payload->setIssuedAt('2024-01-01T00:00:00Z');
        $payload->setExpiration('2024-12-31T23:59:59Z');
        
        $payload->validate(); // Sollte ohne Ausnahme erfolgreich sein
    }

    public function testValidateIssuerThrowsExceptionIfIssuerInvalid()
    {
        $this->expectException(Exception\Payload\InvalidIssuer::class);
        
        $payload = new JwtPayload();
        $payload->setIssuer('wrongIssuer');
        $payload->validateIssuer('expectedIssuer');
    }

    public function testValidateAudienceStringThrowsExceptionIfAudienceInvalid()
    {
        $this->expectException(Exception\Payload\AudienceInvalid::class);
        
        $payload = new JwtPayload();
        $payload->setAudience('wrongAudience');
        $payload->validateAudience('expectedAudience');
    }
    
    public function testValidateAudienceArrayThrowsExceptionIfAudienceInvalid()
    {
        $this->expectException(Exception\Payload\AudienceInvalid::class);
        
        $payload = new JwtPayload();
        $payload->setAudience([
            'wrongAudience',
            'wrongAudience2'
        ]);
        
        $payload->validateAudience([
            'validAudience',
        ]);
    }

    public function testToArray()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')->setAudience('testAudience');
        $payload->setExpiration('2024-12-31T23:59:59Z');

        $array = $payload->toArray();
        $this->assertArrayHasKey('iss', $array);
        $this->assertEquals('testIssuer', $array['iss']);
        $this->assertEquals('testAudience', $array['aud']);
    }

    public function testToJson()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')->setAudience('testAudience');
        $payload->setExpiration('2024-12-31T23:59:59Z');

        $json = $payload->toJson();
        $decoded = json_decode($json, true);
        
        $this->assertArrayHasKey('iss', $decoded);
        $this->assertEquals('testIssuer', $decoded['iss']);
        $this->assertEquals('testAudience', $decoded['aud']);
    }
    
    public function testValidateAudienceSingleMatch()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $payload->setAudience(['validAudience', 'anotherAudience']);
        
        // This should pass because 'validAudience' is present in the audience array
        $payload->validateAudience('validAudience');
    }

    public function testValidateAudienceMultipleMatches()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $payload->setAudience(['validAudience', 'anotherAudience']);
        
        // This should pass because one of the expected audiences matches
        $payload->validateAudience(['noMatch', 'validAudience']);
    }

    public function testValidateAudienceNoMatchThrowsException()
    {
        $this->expectException(Exception\Payload\AudienceInvalid::class);
        
        $payload = new JwtPayload();
        $payload->setAudience(['wrongAudience']);
        
        // Should throw exception because there's no matching audience
        $payload->validateAudience(['expectedAudience']);
    }

    public function testValidateIssuerSuccess()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $payload->setIssuer('expectedIssuer');
        
        // This should pass because the issuer matches
        $payload->validateIssuer('expectedIssuer');
    }

    public function testValidateIssuerNoMatchThrowsException()
    {
        $this->expectException(Exception\Payload\InvalidIssuer::class);
        
        $payload = new JwtPayload();
        $payload->setIssuer('wrongIssuer');
        
        // Should throw exception because issuer does not match
        $payload->validateIssuer('expectedIssuer');
    }

    public function testMissingAudienceThrowsException()
    {
        $this->expectException(Exception\Payload\MissingData::class);
        
        $payload = new JwtPayload();
        // Audience is not set, so this should throw a MissingData exception
        $payload->validateAudience('expectedAudience');
    }

    public function testToArrayIncludesAllFields()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('testIssuer')
                ->setAudience(['aud1', 'aud2'])
                ->setExpiration('2024-12-31T23:59:59Z')
                ->setIssuedAt('2024-01-01T00:00:00Z')
                ->setNotBefore('2024-06-01T12:00:00Z');
        
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
                ->setExpiration('2024-12-31T23:59:59Z')
                ->setIssuedAt('2024-01-01T00:00:00Z')
                ->setNotBefore('2024-06-01T12:00:00Z');
        
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
        $payload->validateAudience('aud2');
    }

    public function testAudienceValidationWithEmptyExpectedArrayThrowsException()
    {        
        $payload = new JwtPayload();
        $payload->setAudience(['aud1', 'aud2']);
        
        $this->expectException(Exception\Payload\AudienceInvalid::class);
        
        // Should throw exception because expected audience is empty
        $payload->validateAudience([]);
    }

    public function testIssuerValidationWithEmptyStringThrowsException()
    {        
        $payload = new JwtPayload();

        $this->expectException(Exception\Payload\EmptyValueException::class);
        
        // Should throw exception because issuer is an empty string
        $payload->setIssuer('');
    }
    
    public function testValidateTokenNotBeforeFutureThrowsException()
    {
        $payload = new JwtPayload();
        $payload->setExpiration('+45 minutes');
        $payload->setNotBefore('+30 minutes');
        
        $this->expectException(Exception\Payload\NotYetValid::class);

        // This should throw an exception because the `nbf` is set in the future
        $payload->validate();
    }

    public function testValidateTokenNotBeforePastSucceeds()
    {
        $payload = (new JwtPayload())
            ->setIssuedAt('now')
            ->setExpiration('+45 minutes')
            ->setNotBefore('-1 hour');
        
        $this->expectException(Exception\Payload\NotBeforeOlderThanIat::class);

        // This should succeed because the `nbf` is set in the past
        $payload->validate();
    }

    public function testValidateTokenExpirationInFutureSucceeds()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $futureDate = (new DateTimeImmutable('+1 hour'))->format(DateTime::ATOM);
        $payload->setExpiration($futureDate);

        // This should succeed because the `exp` is set in the future
        $payload->validate();
    }

    public function testValidateTokenExpiredThrowsException()
    {
        $payload = new JwtPayload();
        $pastDate = (new DateTimeImmutable('-1 hour'))->format(DateTime::ATOM);
        $payload->setExpiration($pastDate);

        $this->expectException(Exception\Payload\Expired::class);
        
        // This should throw an exception because the `exp` is set in the past
        $payload->validate();
    }

    public function testValidateTokenAllTemporalClaimsValid()
    {
        $this->expectNotToPerformAssertions();

        $payload = new JwtPayload();
        $pastDate = (new DateTimeImmutable('-1 hour'))->format(DateTime::ATOM);
        $futureDate = (new DateTimeImmutable('+1 hour'))->format(DateTime::ATOM);

        $payload->setIssuedAt($pastDate);
        $payload->setNotBefore($pastDate);
        $payload->setExpiration($futureDate);

        // This should succeed because all temporal claims are valid
        $payload->validate();
    }

    public function testValidateTokenWithMixedInvalidTemporalClaims()
    {
        $payload = new JwtPayload();
        $pastDate = (new DateTimeImmutable('-2 hours'))->format(DateTime::ATOM);
        $expiredDate = (new DateTimeImmutable('-1 hour'))->format(DateTime::ATOM);

        $payload->setIssuedAt($pastDate);
        $payload->setNotBefore($pastDate);
        $payload->setExpiration($expiredDate);

        $this->expectException(Exception\Payload\Expired::class);
        
        // This should throw an `Expired` exception because `exp` is in the past
        $payload->validate();
    }

    public function testValidateTokenWithoutExpirationThrowsException()
    {
        $payload = new JwtPayload();
        
        $payload->setIssuedAt('-1 hour');
        $payload->setNotBefore('-1 hour');
        
        $this->expectException(Exception\Payload\MissingData::class);

        // This should throw a MissingData exception because `exp` is not set
        $payload->validate();
    }
    
    public function testSetExpirationWithUnixMaxTime()
    {
        $payload = new JwtPayload();
        $dateTime = new DateTimeImmutable('@2147483647'); // Maximale 32-bit Zeit

        $payload->setExpiration($dateTime->format(DateTime::ATOM));
        $this->assertEquals($dateTime->getTimestamp(), $payload->getField('exp'));
    }

    public function testSetNotBeforeWithInvalidDateThrowsException()
    {
        $this->expectException(Exception\Payload\InvalidDateTime::class);

        $payload = new JwtPayload();
        $payload->setNotBefore('invalid-date-format');
    }
}
