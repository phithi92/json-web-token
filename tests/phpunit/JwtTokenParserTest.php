<?php

declare(strict_types=1);

namespace Tests;

require_once "TestCaseWithSecrets.php";

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\JwtTokenParser;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtTokenFactory;

final class JwtTokenParserTest extends TestCaseWithSecrets
{
    public function testParseValidJweToken(): void
    {
        // Simulierter gültiger JWE-Header
        $header = ['alg' => 'dir', 'typ' => 'JWE', 'enc' => 'A256GCM'];
        $headerJson = json_encode($header, JSON_THROW_ON_ERROR);

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
}
