<?php

declare(strict_types=1);

namespace Tests\phpunit\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use PHPUnit\Framework\TestCase;

final class JwtEncryptionDataTest extends TestCase
{
    public function testSetAndGetAad(): void
    {
        $jwtData = new JwtEncryptionData();
        $encodedHeader = 'eyJhbGciOiAiUlMyNTYifQ';

        $this->assertSame($jwtData, $jwtData->setAad($encodedHeader));
        $this->assertSame($encodedHeader, $jwtData->getAad());
    }

    public function testGetAadWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No AAD configured.');

        (new JwtEncryptionData())->getAad();
    }

    public function testSetAndGetIv(): void
    {
        $jwtData = new JwtEncryptionData();
        $iv = 'initialization_vector';

        $this->assertSame($jwtData, $jwtData->setIv($iv));
        $this->assertSame($iv, $jwtData->getIv());
    }

    public function testGetIvWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No IV configured.');

        (new JwtEncryptionData())->getIv();
    }

    public function testSetAndGetCek(): void
    {
        $jwtData = new JwtEncryptionData();
        $cek = 'secret_encryption_key';

        $this->assertSame($jwtData, $jwtData->setCek($cek));
        $this->assertSame($cek, $jwtData->getCek());
    }

    public function testGetCekWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No CEK configured.');

        (new JwtEncryptionData())->getCek();
    }

    public function testSetAndGetEncryptedKey(): void
    {
        $jwtData = new JwtEncryptionData();
        $encryptedKey = 'encrypted_cek_value';

        $this->assertSame($jwtData, $jwtData->setEncryptedKey($encryptedKey));
        $this->assertSame($encryptedKey, $jwtData->getEncryptedKey());
    }

    public function testGetEncryptedKeyWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No EncryptedKey configured.');

        (new JwtEncryptionData())->getEncryptedKey();
    }

    public function testSetAndGetAuthTag(): void
    {
        $jwtData = new JwtEncryptionData();
        $authTag = 'auth_tag_value';

        $this->assertSame($jwtData, $jwtData->setAuthTag($authTag));
        $this->assertSame($authTag, $jwtData->getAuthTag());
    }

    public function testGetAuthTagWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No AuthTag configured.');

        (new JwtEncryptionData())->getAuthTag();
    }

    public function testMethodChaining(): void
    {
        $jwtData = (new JwtEncryptionData())
            ->setCek('cek')
            ->setIv('iv')
            ->setAad('aad')
            ->setEncryptedKey('encrypted')
            ->setAuthTag('tag');

        $this->assertSame('cek', $jwtData->getCek());
        $this->assertSame('iv', $jwtData->getIv());
        $this->assertSame('aad', $jwtData->getAad());
        $this->assertSame('encrypted', $jwtData->getEncryptedKey());
        $this->assertSame('tag', $jwtData->getAuthTag());
    }
}
