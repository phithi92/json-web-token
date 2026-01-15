<?php

declare(strict_types=1);

namespace Tests\phpunit\Token;

use Phithi92\JsonWebToken\Exceptions\Payload\ClaimAlreadyExistsException;
use Phithi92\JsonWebToken\Exceptions\Payload\EncryptedPayloadAlreadySetException;
use Phithi92\JsonWebToken\Exceptions\Payload\EncryptedPayloadNotSetException;
use Phithi92\JsonWebToken\Token\JwtPayload;
use PHPUnit\Framework\TestCase;

final class JwtPayloadTest extends TestCase
{
    public function testToArrayDoesNotImplicitlyAddDefaults(): void
    {
        $payload = new JwtPayload();

        self::assertSame([], $payload->toArray());
        self::assertFalse($payload->hasClaim('iat'));
    }

    public function testToArrayWithDefaultsAddsIatIfMissing(): void
    {
        $payload = new JwtPayload();

        $before = time();
        $arr = $payload->toArrayWithDefaults();
        $after = time();

        self::assertArrayHasKey('iat', $arr);
        self::assertTrue($payload->hasClaim('iat'));

        $iat = $payload->getIssuedAt();
        self::assertNotNull($iat);
        self::assertIsInt($iat, 'iat should be NumericDate int when set via "now" default');
        self::assertGreaterThanOrEqual($before, $iat);
        self::assertLessThanOrEqual($after + 1, $iat); // kleine Toleranz
    }

    public function testAddClaimThrowsIfClaimAlreadyExists(): void
    {
        $payload = new JwtPayload();
        $payload->addClaim('sub', '123');

        $this->expectException(ClaimAlreadyExistsException::class);
        $payload->addClaim('sub', '456');
    }

    public function testSetClaimOverwritesExistingClaim(): void
    {
        $payload = new JwtPayload();
        $payload->addClaim('sub', '123');

        $payload->setClaim('sub', '456');

        self::assertSame('456', $payload->getClaim('sub'));
    }

    public function testIssuerGetterSetter(): void
    {
        $payload = new JwtPayload();
        $payload->setIssuer('issuer-1');

        self::assertSame('issuer-1', $payload->getIssuer());
        self::assertSame('issuer-1', $payload->getClaim('iss'));
    }

    public function testAudienceAcceptsString(): void
    {
        $payload = new JwtPayload();
        $payload->setAudience('app');

        self::assertSame('app', $payload->getAudience());
    }

    public function testAudienceAcceptsListOfStrings(): void
    {
        $payload = new JwtPayload();
        $payload->setAudience(['app-a', 'app-b']);

        $aud = $payload->getAudience();
        self::assertIsArray($aud);
        self::assertSame(['app-a', 'app-b'], $aud);
    }

    public function testSetClaimTimestampAllowsFloatForTimeClaims(): void
    {
        $payload = new JwtPayload();

        $payload->setClaimTimestamp('iat', 123.456);

        $iat = $payload->getIssuedAt();
        self::assertIsFloat($iat);
        self::assertSame(123.456, $iat);
    }

    public function testSetIssuedAtFromStringResultsInNumericDate(): void
    {
        $payload = new JwtPayload();

        $payload->setIssuedAt('now');

        $iat = $payload->getIssuedAt();
        self::assertNotNull($iat);
        self::assertTrue(is_int($iat) || is_float($iat));
    }

    public function testSetExpirationAndNotBeforeProduceNumericDates(): void
    {
        $payload = new JwtPayload();

        $payload->setExpiration('+1 hour');
        $payload->setNotBefore('now');

        $exp = $payload->getExpiration();
        $nbf = $payload->getNotBefore();

        self::assertNotNull($exp);
        self::assertNotNull($nbf);
        self::assertTrue(is_int($exp) || is_float($exp));
        self::assertTrue(is_int($nbf) || is_float($nbf));

        // exp sollte in der Zukunft liegen (sehr grob)
        self::assertGreaterThan(time() - 5, (int) $exp);
    }

    public function testEncryptedPayloadNotSetThrows(): void
    {
        $payload = new JwtPayload();

        $this->expectException(EncryptedPayloadNotSetException::class);
        $payload->getEncryptedPayload();
    }

    public function testSetEncryptedPayloadAndGetEncryptedPayload(): void
    {
        $payload = new JwtPayload();

        $payload->setEncryptedPayload('sealed-1');

        self::assertSame('sealed-1', $payload->getEncryptedPayload());
    }

    public function testSetEncryptedPayloadSameValueIsIdempotent(): void
    {
        $payload = new JwtPayload();

        $payload->setEncryptedPayload('sealed-1');
        $payload->setEncryptedPayload('sealed-1'); // kein Fehler, gleiche Payload

        self::assertSame('sealed-1', $payload->getEncryptedPayload());
    }

    public function testSetEncryptedPayloadDifferentValueWithoutOverwriteThrows(): void
    {
        $payload = new JwtPayload();

        $payload->setEncryptedPayload('sealed-1');

        $this->expectException(EncryptedPayloadAlreadySetException::class);
        $payload->setEncryptedPayload('sealed-2', overwrite: false);
    }

    public function testSetEncryptedPayloadDifferentValueWithOverwriteReplaces(): void
    {
        $payload = new JwtPayload();

        $payload->setEncryptedPayload('sealed-1');
        $payload->setEncryptedPayload('sealed-2', overwrite: true);

        self::assertSame('sealed-2', $payload->getEncryptedPayload());
    }
}
