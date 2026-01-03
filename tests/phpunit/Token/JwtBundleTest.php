<?php

declare(strict_types=1);

namespace Tests\phpunit\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\JwtSignature;
use PHPUnit\Framework\TestCase;

class JwtBundleTest extends TestCase
{
    public function testConstructorInitializesHeaderAndPayload(): void
    {
        $header = new JwtHeader();
        $payload = new JwtPayload();

        $bundle = new JwtBundle($header, $payload);

        $this->assertSame($header, $bundle->getHeader());
        $this->assertSame($payload, $bundle->getPayload());
    }

    public function testConstructorInitializesPayloadIfNull(): void
    {
        $header = new JwtHeader();
        $bundle = new JwtBundle($header);

        $this->assertInstanceOf(JwtPayload::class, $bundle->getPayload());
    }

    public function testEncryptionDataIsInitialized(): void
    {
        $header = new JwtHeader();
        $bundle = new JwtBundle($header);

        $this->assertInstanceOf(JwtEncryptionData::class, $bundle->getEncryption());
    }

    public function testSetAndGetSignature(): void
    {
        $header = new JwtHeader();
        $bundle = new JwtBundle($header);

        $signature = 'test-signature';
        $bundle->setSignature(new JwtSignature($signature));

        $this->assertSame($signature, (string) $bundle->getSignature());
    }

    public function testGetSignatureThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('Signature');

        $header = new JwtHeader();
        $bundle = new JwtBundle($header);

        $bundle->getSignature();
    }

    public function testSetSignatureSupportsMethodChaining(): void
    {
        $header = new JwtHeader();
        $bundle = new JwtBundle($header);

        $result = $bundle->setSignature(new JwtSignature('chained-signature'));

        $this->assertSame($bundle, $result);
    }
}
