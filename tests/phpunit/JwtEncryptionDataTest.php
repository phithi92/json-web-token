<?php

declare(strict_types=1);

namespace Tests\phpunit;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;

class JwtEncryptionDataTest extends TestCase
{
    public function testSetAndGetAad(): void
    {
        $data = new JwtEncryptionData();
        $aad = 'base64url-aad';
        $data->setAad($aad);

        $this->assertSame($aad, $data->getAad());
    }

    public function testSetAndGetIv(): void
    {
        $data = new JwtEncryptionData();
        $iv = 'initialization-vector';
        $data->setIv($iv);

        $this->assertSame($iv, $data->getIv());
    }

    public function testSetAndGetCek(): void
    {
        $data = new JwtEncryptionData();
        $cek = 'content-encryption-key';
        $data->setCek($cek);

        $this->assertSame($cek, $data->getCek());
    }

    public function testSetAndGetEncryptedKey(): void
    {
        $data = new JwtEncryptionData();
        $encryptedKey = 'encrypted-cek';
        $data->setEncryptedKey($encryptedKey);

        $this->assertSame($encryptedKey, $data->getEncryptedKey());
    }

    public function testSetAndGetAuthTag(): void
    {
        $data = new JwtEncryptionData();
        $authTag = 'authentication-tag';
        $data->setAuthTag($authTag);

        $this->assertSame($authTag, $data->getAuthTag());
    }

    public function testGetAadThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('AAD');

        $data = new JwtEncryptionData();
        $data->getAad();
    }

    public function testGetIvThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('IV');

        $data = new JwtEncryptionData();
        $data->getIv();
    }

    public function testGetCekThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('CEK');

        $data = new JwtEncryptionData();
        $data->getCek();
    }

    public function testGetEncryptedKeyThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('EncryptedKey');

        $data = new JwtEncryptionData();
        $data->getEncryptedKey();
    }

    public function testGetAuthTagThrowsExceptionIfNotSet(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('AuthTag');

        $data = new JwtEncryptionData();
        $data->getAuthTag();
    }

    public function testMethodChaining(): void
    {
        $data = (new JwtEncryptionData())
            ->setAad('aad')
            ->setIv('iv')
            ->setCek('cek')
            ->setEncryptedKey('encrypted')
            ->setAuthTag('tag');

        $this->assertSame('aad', $data->getAad());
        $this->assertSame('iv', $data->getIv());
        $this->assertSame('cek', $data->getCek());
        $this->assertSame('encrypted', $data->getEncryptedKey());
        $this->assertSame('tag', $data->getAuthTag());
    }
}
