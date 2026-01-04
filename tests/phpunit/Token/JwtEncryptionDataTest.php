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
        $encodedHeader = 'eyJhbGciOiAiUlMyNTYifQ';

        $jwtData = new JwtEncryptionData(aad: $encodedHeader);

        $withAad = $jwtData->withAad($encodedHeader);

        $this->assertSame($encodedHeader, $withAad->getAad());
    }

    public function testGetAadWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No aad configured.');

        (new JwtEncryptionData())->getAad();
    }

    public function testSetAndGetIv(): void
    {
        $jwtData = new JwtEncryptionData();
        $iv = 'initialization_vector';

        $withIv = $jwtData->withIv($iv);

        $this->assertSame($iv, $withIv->getIv());
    }

    public function testGetIvWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No iv configured.');

        (new JwtEncryptionData())->getIv();
    }

    public function testSetAndGetCek(): void
    {
        $jwtData = new JwtEncryptionData();
        $cek = 'secret_encryption_key';

        $withCek = $jwtData->withCek($cek);

        $this->assertSame($cek, $withCek->getCek());
    }

    public function testGetCekWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No cek configured.');

        (new JwtEncryptionData())->getCek();
    }

    public function testSetAndGetEncryptedKey(): void
    {
        $jwtData = new JwtEncryptionData();
        $encryptedKey = 'encrypted_cek_value';

        $withEncryptedKey = $jwtData->withEncryptedKey($encryptedKey);

        $this->assertSame($encryptedKey, $withEncryptedKey->getEncryptedKey());
    }

    public function testGetEncryptedKeyWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No encrypted_key configured.');

        (new JwtEncryptionData())->getEncryptedKey();
    }

    public function testSetAndGetAuthTag(): void
    {
        $jwtData = new JwtEncryptionData();
        $authTag = 'auth_tag_value';

        $withAuthTag = $jwtData->withAuthTag($authTag);

        $this->assertSame($authTag, $withAuthTag->getAuthTag());
    }

    public function testGetAuthTagWithoutSetThrowsException(): void
    {
        $this->expectException(MissingTokenPart::class);
        $this->expectExceptionMessage('No tag configured.');

        (new JwtEncryptionData())->getAuthTag();
    }

    public function testMethodChaining(): void
    {
        $jwtData = new JwtEncryptionData(
            cek: 'cek',
            iv: 'iv',
            aad: 'aad',
            encryptedKey: 'encrypted',
            authTag: 'tag'
        );

        $this->assertSame('cek', $jwtData->getCek());
        $this->assertSame('iv', $jwtData->getIv());
        $this->assertSame('aad', $jwtData->getAad());
        $this->assertSame('encrypted', $jwtData->getEncryptedKey());
        $this->assertSame('tag', $jwtData->getAuthTag());
    }
}
