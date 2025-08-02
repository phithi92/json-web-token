<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\Exceptions;
use Phithi92\JsonWebToken\JwtValidator;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
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

    public function testFromJsonCreatesValidPayload()
    {
        $json = json_encode([
            'iss' => 'issuerTest',
            'aud' => ['aud1', 'aud2'],
            'custom' => 'customValue',
        ]);

        $payload = JwtPayload::fromJson($json);

        $this->assertEquals('issuerTest', $payload->getClaim('iss'));
        $this->assertEquals(['aud1', 'aud2'], $payload->getClaim('aud'));
        $this->assertEquals('customValue', $payload->getClaim('custom'));
    }

    public function testFromJsonFailsOnEmptyString()
    {
        $this->expectException(InvalidFormatException::class);

        JwtPayload::fromJson('');
    }

    public function testFromJsonFailsOnMalformedUtf8()
    {
        // Enthält absichtlich ungültige UTF-8-Bytefolge
        $malformedJson = "\xB1\x31\x31"; // ungültig, zerschneidet ein Multibyte-Zeichen

        $this->expectException(InvalidFormatException::class);

        JwtPayload::fromJson($malformedJson);
    }

    public function testFromJsonInvalidJsonThrowsException()
    {
        $this->expectException(InvalidFormatException::class);
        JwtPayload::fromJson('{"iss": invalid json}');
    }

    public function testFromArrayCreatesValidPayload()
    {
        $array = [
            'iss' => 'arrayIssuer',
            'aud' => 'arrayAudience',
            'foo' => 'bar',
        ];

        $payload = JwtPayload::fromArray($array);

        $this->assertEquals('arrayIssuer', $payload->getIssuer());
        $this->assertEquals('arrayAudience', $payload->getAudience());
        $this->assertEquals('bar', $payload->getClaim('foo'));
    }

    public function testAddEmptyClaimThrowsException()
    {
        $this->expectException(Exceptions\Payload\EmptyFieldException::class);
        (new JwtPayload())->addClaim('empty', '');
    }

    public function testAddInvalidClaimTypeThrowsException()
    {
        $this->expectException(\TypeError::class);

        (new JwtPayload())->addClaim('invalid', new \stdClass());
    }

    public function testEncryptedPayloadSetAndGet()
    {
        $payload = (new JwtPayload())->setEncryptedPayload('ENCRYPTED123');
        $this->assertEquals('ENCRYPTED123', $payload->getEncryptedPayload());
    }

    public function testClaimOverwriteFalseDoesNotReplaceExisting()
    {
        $payload = new JwtPayload();
        $payload->addClaim('claim1', 'original');
        $payload->addClaim('claim1', 'new'); // overwrite = false

        $this->assertEquals('original', $payload->getClaim('claim1'));
    }

    public function testHasClaimReturnsCorrectResult()
    {
        $payload = new JwtPayload();
        $this->assertFalse($payload->hasClaim('missing'));

        $payload->addClaim('exists', 'value');
        $this->assertTrue($payload->hasClaim('exists'));
    }

    public function testIssuedAtAutoSetIfMissingInToArray()
    {
        $payload = new JwtPayload();
        $payload->setIssuer('issuer');

        $array = $payload->toArray();

        $this->assertArrayHasKey('iat', $array);
        $this->assertGreaterThan(0, $array['iat']);
    }
}
