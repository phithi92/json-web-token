<?php

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;

class JwtTokenContainerTest extends TestCase
{
    public function testConstructorWithPayload()
    {
        $payload = new JwtPayload();
        $jwtToken = new JwtTokenContainer($payload);

        // Überprüfe, ob der Payload gesetzt wurde
        $this->assertSame($payload, $jwtToken->getPayload());
    }

    public function testSetAndGetEncryptedPayload()
    {
        $jwtToken = new JwtTokenContainer();
        $encryptedPayload = 'encryptedPayload123';
        
        $jwtToken->setEncryptedPayload($encryptedPayload);

        // Überprüfe, ob der verschlüsselte Payload korrekt gesetzt und abgerufen wurde
        $this->assertEquals($encryptedPayload, $jwtToken->getEncryptedPayload());
    }

    public function testSetAndGetHeader()
    {
        $jwtHeader = new JwtHeader('HS256', 'JWT');
        $jwtToken = new JwtTokenContainer();
        
        $jwtToken->setHeader($jwtHeader);

        // Überprüfe, ob der Header korrekt gesetzt und abgerufen wurde
        $this->assertSame($jwtHeader, $jwtToken->getHeader());
    }

    public function testSetAndGetSignature()
    {
        $jwtToken = new JwtTokenContainer();
        $signature = 'signature123';

        $jwtToken->setSignature($signature);

        // Überprüfe, ob die Signatur korrekt gesetzt und abgerufen wurde
        $this->assertEquals($signature, $jwtToken->getSignature());
    }

    public function testSetAndGetIv()
    {
        $jwtToken = new JwtTokenContainer();
        $iv = 'iv123';

        $jwtToken->setIv($iv);

        // Überprüfe, ob der IV korrekt gesetzt und abgerufen wurde
        $this->assertEquals($iv, $jwtToken->getIv());
    }

    public function testSetAndGetCek()
    {
        $jwtToken = new JwtTokenContainer();
        $cek = 'cek123';

        $jwtToken->setCek($cek);

        // Überprüfe, ob der CEK korrekt gesetzt und abgerufen wurde
        $this->assertEquals($cek, $jwtToken->getCek());
    }

    public function testSetAndGetEncryptedKey()
    {
        $jwtToken = new JwtTokenContainer();
        $encryptedKey = 'encryptedKey123';

        $jwtToken->setEncryptedKey($encryptedKey);

        // Überprüfe, ob der verschlüsselte Schlüssel korrekt gesetzt und abgerufen wurde
        $this->assertEquals($encryptedKey, $jwtToken->getEncryptedKey());
    }

    public function testSetAndGetAuthTag()
    {
        $jwtToken = new JwtTokenContainer();
        $authTag = 'authTag123';

        $jwtToken->setAuthTag($authTag);

        // Überprüfe, ob das Authentifizierungs-Tag korrekt gesetzt und abgerufen wurde
        $this->assertEquals($authTag, $jwtToken->getAuthTag());
    }

    public function testEmptyAuthTag()
    {
        $jwtToken = new JwtTokenContainer();

        // Überprüfe, dass das Authentifizierungs-Tag standardmäßig null ist
        $this->assertNull($jwtToken->getAuthTag());
    }
}
