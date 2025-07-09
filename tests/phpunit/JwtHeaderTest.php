<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtHeader;

class JwtHeaderTest extends TestCase
{
    public function testConstructorWithParameters()
    {
        $jwtHeader = new JwtHeader('HS256', 'JWT');

        // Überprüfe, ob die gesetzten Werte korrekt sind
        $this->assertEquals('HS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWT', $jwtHeader->getType());
    }

    public function testConstructorWithoutParameters()
    {
        $jwtHeader = new JwtHeader();

        // Standardwerte überprüfen
        $this->assertEquals('', $jwtHeader->getAlgorithm());
        $this->assertEquals('', $jwtHeader->getType());
    }

    public function testSetType()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setType('JWS');

        // Überprüfe, ob der Typ korrekt gesetzt wurde
        $this->assertEquals('JWS', $jwtHeader->getType());
    }

    public function testSetAlgorithm()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setAlgorithm('RS256');

        // Überprüfe, ob der Algorithmus korrekt gesetzt wurde
        $this->assertEquals('RS256', $jwtHeader->getAlgorithm());
    }

    public function testSetEnc()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setEnc('A256GCM');

        // Überprüfe, ob die Verschlüsselung korrekt gesetzt wurde
        $this->assertEquals('A256GCM', $jwtHeader->getEnc());
    }

    public function testToArray()
    {
        $jwtHeader = new JwtHeader('HS256', 'JWT');
        $headerArray = $jwtHeader->toArray();

        // Überprüfe, ob das Array korrekt ist
        $this->assertArrayHasKey('alg', $headerArray);
        $this->assertArrayHasKey('typ', $headerArray);
        $this->assertEquals('HS256', $headerArray['alg']);
        $this->assertEquals('JWT', $headerArray['typ']);
    }

    public function testToJson()
    {
        $jwtHeader = new JwtHeader('HS256', 'JWT');
        $json = $jwtHeader->toJson();

        // Überprüfe, ob die JSON-Darstellung korrekt ist
        $this->assertJson($json);
        $this->assertStringContainsString('"alg":"HS256"', $json);
        $this->assertStringContainsString('"typ":"JWT"', $json);
    }

    public function testFromJson()
    {
        $json = '{"alg":"HS256","typ":"JWT"}';
        $jwtHeader = JwtHeader::fromJson($json);

        // Überprüfe, ob die Werte korrekt aus dem JSON extrahiert wurden
        $this->assertEquals('HS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWT', $jwtHeader->getType());
    }

    public function testFromJsonWithEnc()
    {
        $json = '{"alg":"HS256","typ":"JWS","enc":"A256GCM"}';
        $jwtHeader = JwtHeader::fromJson($json);

        // Überprüfe, ob die Verschlüsselung korrekt aus dem JSON extrahiert wurde
        $this->assertEquals('HS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWS', $jwtHeader->getType());
        $this->assertEquals('A256GCM', $jwtHeader->getEnc());
    }
}
