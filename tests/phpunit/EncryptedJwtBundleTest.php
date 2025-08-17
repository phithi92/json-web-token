<?php

declare(strict_types=1);

namespace Tests\phpunit;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;

class EncryptedJwtBundleTest extends TestCase
{
    public function testConstructorInitializesHeaderAndPayload(): void
    {
        $header = new JwtHeader();
        $payload = new JwtPayload();

        $bundle = new EncryptedJwtBundle($header, $payload);

        $this->assertSame($header, $bundle->getHeader());
        $this->assertSame($payload, $bundle->getPayload());
    }

    public function testConstructorInitializesPayloadIfNull(): void
    {
        $header = new JwtHeader();
        $bundle = new EncryptedJwtBundle($header);

        $this->assertInstanceOf(JwtPayload::class, $bundle->getPayload());
    }

    public function testEncryptionDataIsInitialized(): void
    {
        $header = new JwtHeader();
        $bundle = new EncryptedJwtBundle($header);

        $this->assertInstanceOf(JwtEncryptionData::class, $bundle->getEncryption());
    }

    public function testSetAndGetSignature(): void
    {
        $header = new JwtHeader();
        $bundle = new EncryptedJwtBundle($header);

        $signature = 'test-signature';
        $bundle->setSignature($signature);

        $this->assertSame($signature, $bundle->getSignature());
    }

    public function testGetSignatureThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('Signature');

        $header = new JwtHeader();
        $bundle = new EncryptedJwtBundle($header);

        $bundle->getSignature();
    }

    public function testSetSignatureSupportsMethodChaining(): void
    {
        $header = new JwtHeader();
        $bundle = new EncryptedJwtBundle($header);

        $result = $bundle->setSignature('chained-signature');

        $this->assertSame($bundle, $result);
    }
}
