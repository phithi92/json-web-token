<?php

declare(strict_types=1);

namespace Tests\phpunit;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidKidLengthException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;

class JwtHeaderTest extends TestCase
{
    public function testSetType()
    {
        $jwtHeader = new JwtHeader();
        $this->assertSame($jwtHeader, $jwtHeader->setType('JWS'));
        $this->assertEquals('JWS', $jwtHeader->getType());
    }

    public function testSetAlgorithm()
    {
        $jwtHeader = new JwtHeader();
        $this->assertSame($jwtHeader, $jwtHeader->setAlgorithm('RS256'));
        $this->assertEquals('RS256', $jwtHeader->getAlgorithm());
    }

    public function testSetEnc()
    {
        $jwtHeader = new JwtHeader();
        $this->assertSame($jwtHeader, $jwtHeader->setEnc('A256GCM'));
        $this->assertEquals('A256GCM', $jwtHeader->getEnc());
    }

    public function testSetValidKid()
    {
        $jwtHeader = new JwtHeader();
        $this->assertSame($jwtHeader, $jwtHeader->setKid('abc_123-KID'));
        $this->assertEquals('abc_123-KID', $jwtHeader->getKid());
        $this->assertTrue($jwtHeader->hasKid());
    }

    public function testSetKidWithInvalidCharacters()
    {
        $this->expectException(InvalidKidFormatException::class);
        (new JwtHeader())->setKid('invalid kid!');
    }

    public function testSetKidWithTooShortLength()
    {
        $this->expectException(InvalidKidLengthException::class);
        (new JwtHeader())->setKid('ab');
    }

    public function testSetKidWithTooLongLength()
    {
        $this->expectException(InvalidKidLengthException::class);
        (new JwtHeader())->setKid(str_repeat('a', 65));
    }

    public function testToArrayWithAllFields()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader
            ->setAlgorithm('HS256')
            ->setType('JWT')
            ->setEnc('A256GCM')
            ->setKid('key123');

        $array = $jwtHeader->toArray();

        $this->assertEquals([
            'alg' => 'HS256',
            'typ' => 'JWT',
            'enc' => 'A256GCM',
            'kid' => 'key123',
        ], $array);
    }

    public function testToJson()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setAlgorithm('HS256')->setType('JWS');

        $json = $jwtHeader->toJson();

        $this->assertJson($json);
        $this->assertStringContainsString('"alg":"HS256"', $json);
        $this->assertStringContainsString('"typ":"JWS"', $json);
    }

    public function testFromJsonMinimal()
    {
        $json = '{"alg":"HS256","typ":"JWS"}';
        $jwtHeader = JwtHeader::fromJson($json);

        $this->assertEquals('HS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWS', $jwtHeader->getType());
        $this->assertEmpty($jwtHeader->getEnc());
        $this->assertEmpty($jwtHeader->getKid());
    }

    public function testFromJsonWithEncAndKid()
    {
        $json = '{"alg":"HS512","typ":"JWT","enc":"A256CBC","kid":"my_kid-123"}';
        $jwtHeader = JwtHeader::fromJson($json);

        $this->assertEquals('HS512', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWT', $jwtHeader->getType());
        $this->assertEquals('A256CBC', $jwtHeader->getEnc());
        $this->assertEquals('my_kid-123', $jwtHeader->getKid());
    }

    public function testFromJsonWithNonStringValue()
    {
        $this->expectException(InvalidFormatException::class);
        JwtHeader::fromJson('{"alg":"HS256","typ":"JWT","enc":123}');
    }

    public function testFromJsonFailsOnEmptyString()
    {
        $this->expectException(InvalidFormatException::class);

        JwtHeader::fromJson('');
    }

    public function testFromJsonFailsOnMalformedUtf8()
    {
        // Enthält absichtlich ungültige UTF-8-Bytefolge
        $malformedJson = "\xB1\x31\x31"; // ungültig, zerschneidet ein Multibyte-Zeichen

        $this->expectException(InvalidFormatException::class);

        JwtHeader::fromJson($malformedJson);
    }

    public function testFromJsonWithInvalidJson()
    {
        $this->expectException(InvalidFormatException::class);
        JwtHeader::fromJson('{"iss": invalid json}');
    }

    public function testFromArray()
    {
        $data = [
            'alg' => 'RS256',
            'typ' => 'JWT',
            'enc' => 'A128GCM',
            'kid' => 'key_id-456',
        ];

        $jwtHeader = JwtHeader::fromArray($data);

        $this->assertEquals('RS256', $jwtHeader->getAlgorithm());
        $this->assertEquals('JWT', $jwtHeader->getType());
        $this->assertEquals('A128GCM', $jwtHeader->getEnc());
        $this->assertEquals('key_id-456', $jwtHeader->getKid());
    }

    public function testToArrayOmitsEmptyFields()
    {
        $jwtHeader = new JwtHeader();
        $jwtHeader->setAlgorithm('HS256');

        $array = $jwtHeader->toArray();

        $this->assertEquals(['alg' => 'HS256'], $array);
        $this->assertArrayNotHasKey('typ', $array);
        $this->assertArrayNotHasKey('enc', $array);
        $this->assertArrayNotHasKey('kid', $array);
    }

    public function testJsonRoundTrip()
    {
        $original = new JwtHeader();
        $original->setAlgorithm('RS512')->setType('JWT')->setEnc('A192CBC')->setKid('abc123');

        $json = $original->toJson();
        $parsed = JwtHeader::fromJson($json);

        $this->assertEquals($original->toArray(), $parsed->toArray());
    }

    public function testHasKid()
    {
        $header = new JwtHeader();
        $this->assertFalse($header->hasKid());

        $header->setKid('validKID');
        $this->assertTrue($header->hasKid());
    }
}
