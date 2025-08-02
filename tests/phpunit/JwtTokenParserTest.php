<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\JwtTokenParser;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;
use Tests\phpunit\TestCaseWithSecrets;

final class JwtTokenParserTest extends TestCaseWithSecrets
{
    public function testParseValidJweToken(): void
    {
        // Simulierter gültiger JWE-Header
        $header = ['alg' => 'dir', 'typ' => 'JWE', 'enc' => 'A256GCM','kid' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),           // Header
            Base64UrlEncoder::encode('cek_or_encrypted_key'),// CEK oder Encrypted Key
            Base64UrlEncoder::encode('iv123'),               // IV
            Base64UrlEncoder::encode('ciphertext'),          // Ciphertext
            Base64UrlEncoder::encode('authtag'),             // AuthTag
        ];

        $jwt = implode('.', $parts);

        $bundle = JwtTokenParser::parse($jwt);

        $this->assertInstanceOf(EncryptedJwtBundle::class, $bundle);
        $this->assertEquals('JWE', $bundle->getHeader()->getType());
    }

    public function testParseValidJweTokenWithoutType(): void
    {
        // Simulierter gültiger JWE-Header
        $header = ['alg' => 'dir', 'enc' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),           // Header
            Base64UrlEncoder::encode('cek_or_encrypted_key'),// CEK oder Encrypted Key
            Base64UrlEncoder::encode('iv123'),               // IV
            Base64UrlEncoder::encode('ciphertext'),          // Ciphertext
            Base64UrlEncoder::encode('authtag'),             // AuthTag
        ];

        $jwt = implode('.', $parts);

        $bundle = JwtTokenParser::parse($jwt);

        $this->assertInstanceOf(EncryptedJwtBundle::class, $bundle);
    }


    public function testParseInvalidTokenThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);

        // Ungültige Struktur (nur 2 Teile)
        $invalidToken = 'part1.part2';

        JwtTokenParser::parse($invalidToken);
    }

    public function testSerializeJweToken(): void
    {
        // Setup Header + Payload
        $payload = new JwtPayload();

        $bundle = JwtTokenFactory::createToken($this->manager, $payload, 'A256GCM');

        $token = JwtTokenParser::serialize($bundle);

        $this->assertIsString($token);
        $this->assertCount(5, explode('.', $token));
    }

    public function testInvalidBase64InTokenPartThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);

        $parts = [
            '!!invalid_base64@@', // ungültig
            Base64UrlEncoder::encode('key'),
            Base64UrlEncoder::encode('iv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('authtag'),
        ];

        JwtTokenParser::parse(implode('.', $parts));
    }

    public function testInvalidJsonInHeaderThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);

        $invalidJson = '{"alg": "dir", "typ": "JWE",'; // fehlendes schließendes Objekt
        $parts = [
            Base64UrlEncoder::encode($invalidJson),
            Base64UrlEncoder::encode('key'),
            Base64UrlEncoder::encode('iv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('authtag'),
        ];

        JwtTokenParser::parse(implode('.', $parts));
    }

    public function testParseDirectAlgSetsCek(): void
    {
        $cek = 'my_cek_secret';
        $header = ['alg' => 'dir', 'typ' => 'JWE', 'enc' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),
            Base64UrlEncoder::encode($cek),
            Base64UrlEncoder::encode('iv123'),
            Base64UrlEncoder::encode('ciphertext123'),
            Base64UrlEncoder::encode('authtag123'),
        ];

        $bundle = JwtTokenParser::parse(implode('.', $parts));

        $this->assertEquals($cek, $bundle->getEncryption()->getCek());
    }

    public function testJwsWithInvalidJsonPayloadThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);

        $header = ['alg' => 'HS256', 'typ' => 'JWS'];
        $headerJson = JsonEncoder::encode($header);

        $invalidPayload = '{"sub": "user"'; // ungültiges JSON
        $signature = 'dummy_signature';

        $parts = [
            Base64UrlEncoder::encode($headerJson),
            Base64UrlEncoder::encode($invalidPayload),
            Base64UrlEncoder::encode($signature),
        ];

        JwtTokenParser::parse(implode('.', $parts));
    }

    public function testInvalidTypInHeaderThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);

        $header = ['alg' => 'none', 'typ' => 'XYZ'];
        $payload = ['data' => 'value'];
        $signature = 'sig';

        $parts = [
            Base64UrlEncoder::encode(json_encode($header, JSON_THROW_ON_ERROR)),
            Base64UrlEncoder::encode(json_encode($payload, JSON_THROW_ON_ERROR)),
            Base64UrlEncoder::encode($signature),
        ];

        JwtTokenParser::parse(implode('.', $parts));
    }

    public function testParseEmptyTokenThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);
        JwtTokenParser::parse('');
    }

    public function testParseEmptyArrayThrowsException(): void
    {
        $this->expectException(InvalidFormatException::class);
        JwtTokenParser::parse([]);
    }
}
