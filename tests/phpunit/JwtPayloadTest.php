<?php

declare(strict_types=1);

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\Exceptions;

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
        $this->expectException(Exceptions\Payload\ValueNotFoundException::class);
        
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
        $this->expectException(Exceptions\Payload\InvalidIssuerException::class);
        
        $payload = new JwtPayload();
        $payload->setIssuer('wrongIssuer');
        $payload->validateIssuer('expectedIssuer');
    }

    public function testValidateAudienceStringThrowsExceptionIfAudienceInvalid()
    {
        $this->expectException(Exceptions\Payload\InvalidAudienceException::class);
        
        $payload = new JwtPayload();
        $payload->setAudience('wrongAudience');
        $payload->validateAudience('expectedAudience');
    }
    
    public function testValidateAudienceArrayThrowsExceptionIfAudienceInvalid()
    {
        $this->expectException(Exceptions\Payload\InvalidAudienceException::class);
        
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
        $this->expectException(Exceptions\Payload\InvalidAudienceException::class);
        
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
        $this->expectException(Exceptions\Payload\InvalidIssuerException::class);
        
        $payload = new JwtPayload();
        $payload->setIssuer('wrongIssuer');
        
        // Should throw exception because issuer does not match
        $payload->validateIssuer('expectedIssuer');
    }

    public function testMissingAudienceThrowsException()
    {
        $this->expectException(Exceptions\Payload\InvalidAudienceException::class);
        
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
        
        $this->expectException(Exceptions\Payload\InvalidAudienceException::class);
        
        // Should throw exception because expected audience is empty
        $payload->validateAudience([]);
    }

    public function testIssuerValidationWithEmptyStringThrowsException()
    {        
        $payload = new JwtPayload();

        $this->expectException(Exceptions\Payload\EmptyFieldException::class);
        
        // Should throw exception because issuer is an empty string
        $payload->setIssuer('');
    }
    
    public function testValidateTokenNotBeforeFutureThrowsException()
    {
        $payload = (new JwtPayload())
            ->setIssuedAt('now')
            ->setNotBefore('+1 minutes')
            ->setExpiration('+2 minutes');
        
        $this->expectException(Exceptions\Payload\NotYetValidException::class);

        // This should throw an exception because the `nbf` is set in the future
        $payload->validate();
    }

    public function testValidateTokenNotBeforePastSucceeds()
    {
        $payload = (new JwtPayload())
            ->setIssuedAt('+1 minutes')
            ->setExpiration('+1 minutes')
            ->setNotBefore('now');
        
        $this->expectException(Exceptions\Payload\NotBeforeOlderThanIatException::class);

        // This should succeed because the `nbf` is set in the past
        $payload->validate();
    }

    public function testValidateTokenExpirationInFutureSucceeds()
    {
        $this->expectNotToPerformAssertions();
        
        $payload = (new JwtPayload())
                ->setIssuedAt('now')
                ->setExpiration('+1 minutes');

        // This should succeed because the `exp` is set in the future
        $payload->validate();
    }

    public function testValidateTokenExpiredThrowsException()
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-2 minutes')
                ->setExpiration('-1 minutes');

        $this->expectException(Exceptions\Payload\ExpiredPayloadException::class);
        
        // This should throw an exception because the `exp` is set in the past
        $payload->validate();
    }

    public function testValidateTokenAllTemporalClaimsValid()
    {
        $this->expectNotToPerformAssertions();

        $payload = (new JwtPayload())
                ->setIssuedAt('-1 minutes')
                ->setNotBefore('-1 minutes')
                ->setExpiration('+1 minutes');

        // This should succeed because all temporal claims are valid
        $payload->validate();
    }

    public function testValidateTokenWithMixedInvalidTemporalClaims()
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-2 minutes')
                ->setNotBefore('-2 minutes')
                ->setExpiration('-1 minutes');

        $this->expectException(Exceptions\Payload\ExpiredPayloadException::class);
        
        // This should throw an `Expired` exception because `exp` is in the past
        $payload->validate();
    }

    public function testValidateTokenWithoutExpirationThrowsException()
    {
        $payload = (new JwtPayload())
                ->setIssuedAt('-1 minutes')
                ->setNotBefore('-1 minutes');
        
        $this->expectException(Exceptions\Payload\ValueNotFoundException::class);

        // This should throw a MissingData exception because `exp` is not set
        $payload->validate();
    }
    
    public function testSetExpirationWithUnixMaxTime()
    {
        $dateTime = new DateTimeImmutable('@2147483647'); // Maximale 32-bit Zeit
        
        $payload = (new JwtPayload())
                ->setExpiration($dateTime->format(DateTime::ATOM));
        
        $this->assertEquals($dateTime->getTimestamp(), $payload->getField('exp'));
    }

    public function testSetNotBeforeWithInvalidDateThrowsException()
    {
        $this->expectException(Exceptions\Payload\InvalidDateTimeException::class);

        (new JwtPayload())
                ->setNotBefore('invalid-date-format');
    }
}
