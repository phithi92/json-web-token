<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtHeader;

class JwtHeaderTest extends TestCase
{
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

    public function testSetKid()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setKid('sdsadad');

        // Überprüfe, ob die Verschlüsselung korrekt gesetzt wurde
        $this->assertEquals('sdsadad', $jwtHeader->getKid());
    }

    public function testToArray()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setAlgorithm('HS256');
        $jwtHeader->setType('JWS');
        $headerArray = $jwtHeader->toArray();

        // Überprüfe, ob das Array korrekt ist
        $this->assertArrayHasKey('alg', $headerArray);
        $this->assertArrayHasKey('typ', $headerArray);
        $this->assertEquals('HS256', $headerArray['alg']);
        $this->assertEquals('JWS', $headerArray['typ']);
    }

    public function testToJson()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setAlgorithm('HS256');
        $jwtHeader->setType('JWS');
        $json = $jwtHeader->toJson();

        // Überprüfe, ob die JSON-Darstellung korrekt ist
        $this->assertJson($json);
        $this->assertStringContainsString('"alg":"HS256"', $json);
        $this->assertStringContainsString('"typ":"JWS"', $json);
    }

    public function testFromJson()
    {
        $json = '{"alg":"HS256","typ":"JWS"}';
        $jwtHeader = JwtHeader::fromJson($json);

        // Überprüfe, ob die Werte korrekt aus dem JSON extrahiert wurden
        $this->assertEquals('HS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWS', $jwtHeader->getType());
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
