<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Codec;

use Phithi92\JsonWebToken\Exceptions\Token\MalformedTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Token\Codec\JwtBundleCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Tests\phpunit\TestCaseWithSecrets;

use function explode;
use function implode;
use function json_encode;

final class JwtTokenCodecTest extends TestCaseWithSecrets
{
    public function testParseValidJweToken(): void
    {
        // Simulierter gültiger JWE-Header
        $header = ['alg' => 'dir', 'typ' => 'JWE', 'enc' => 'A256GCM', 'kid' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),           // Header
            Base64UrlEncoder::encode('cek_or_encrypted_key'), // CEK oder Encrypted Key
            Base64UrlEncoder::encode('iv123'),               // IV
            Base64UrlEncoder::encode('ciphertext'),          // Ciphertext
            Base64UrlEncoder::encode('authtag'),             // AuthTag
        ];

        $jwt = implode('.', $parts);

        $bundle = JwtBundleCodec::parse($jwt);

        $this->assertInstanceOf(JwtBundle::class, $bundle);
        $this->assertEquals('JWE', $bundle->getHeader()->getType());
    }

    public function testParseValidJweTokenWithoutType(): void
    {
        // Simulierter gültiger JWE-Header
        $header = ['alg' => 'dir', 'enc' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),           // Header
            Base64UrlEncoder::encode('cek_or_encrypted_key'), // CEK oder Encrypted Key
            Base64UrlEncoder::encode('iv123'),               // IV
            Base64UrlEncoder::encode('ciphertext'),          // Ciphertext
            Base64UrlEncoder::encode('authtag'),             // AuthTag
        ];

        $jwt = implode('.', $parts);

        $bundle = JwtBundleCodec::parse($jwt);

        $this->assertInstanceOf(JwtBundle::class, $bundle);
    }

    public function testParseInvalidTokenThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        // Ungültige Struktur (nur 2 Teile)
        $invalidToken = 'part1.part2';

        JwtBundleCodec::parse($invalidToken);
    }

    public function testSerializeJweToken(): void
    {

        $bundleFactory = new \Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer($this->manager);
        $bundle = $bundleFactory->issue('A256GCM', new JwtPayload());

        $token = JwtBundleCodec::serialize($bundle);

        $this->assertIsString($token);
        $this->assertCount(5, explode('.', $token));
    }

    public function testInvalidBase64InTokenPartThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        $parts = [
            '!!invalid_base64@@', // ungültig
            Base64UrlEncoder::encode('key'),
            Base64UrlEncoder::encode('iv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('authtag'),
        ];

        JwtBundleCodec::parse(implode('.', $parts));
    }

    public function testInvalidJsonInHeaderThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        $invalidJson = '{"alg": "dir", "typ": "JWE",'; // fehlendes schließendes Objekt
        $parts = [
            Base64UrlEncoder::encode($invalidJson),
            Base64UrlEncoder::encode('key'),
            Base64UrlEncoder::encode('iv'),
            Base64UrlEncoder::encode('ciphertext'),
            Base64UrlEncoder::encode('authtag'),
        ];

        JwtBundleCodec::parse(implode('.', $parts));
    }

    public function testParseDirectAlgDoesNotUseEncryptedKeyPart(): void
    {
        $header = ['alg' => 'dir', 'typ' => 'JWE', 'enc' => 'A256GCM'];
        $headerJson = JsonEncoder::encode($header);

        $parts = [
            Base64UrlEncoder::encode($headerJson),
            '', // encrypted_key MUST be empty for dir
            Base64UrlEncoder::encode('iv123'),
            Base64UrlEncoder::encode('ciphertext123'),
            Base64UrlEncoder::encode('authtag123'),
        ];

        $bundle = JwtBundleCodec::parse(implode('.', $parts));

        $this->expectException(MissingTokenPart::class);
        // parser should not set a CEK from token for dir
        $bundle->getEncryption()->getEncryptedKey();

        $this->expectException(MissingTokenPart::class);
        // and CEK should remain unset at parse-time (comes from key store later)
        $bundle->getEncryption()->getCek();
    }

    public function testJwsWithInvalidJsonPayloadThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        $header = ['alg' => 'HS256', 'typ' => 'JWS'];
        $headerJson = JsonEncoder::encode($header);

        $invalidPayload = '{"sub": "user"'; // ungültiges JSON
        $signature = 'dummy_signature';

        $parts = [
            Base64UrlEncoder::encode($headerJson),
            Base64UrlEncoder::encode($invalidPayload),
            Base64UrlEncoder::encode($signature),
        ];

        JwtBundleCodec::parse(implode('.', $parts));
    }

    public function testInvalidTypInHeaderThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);

        $header = ['alg' => 'none', 'typ' => 'XYZ'];
        $payload = ['data' => 'value'];
        $signature = 'sig';

        $parts = [
            Base64UrlEncoder::encode(json_encode($header, JSON_THROW_ON_ERROR)),
            Base64UrlEncoder::encode(json_encode($payload, JSON_THROW_ON_ERROR)),
            Base64UrlEncoder::encode($signature),
        ];

        JwtBundleCodec::parse(implode('.', $parts));
    }

    public function testParseEmptyTokenThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);
        JwtBundleCodec::parse('');
    }

    public function testParseEmptyArrayThrowsException(): void
    {
        $this->expectException(MalformedTokenException::class);
        JwtBundleCodec::parse([]);
    }
}
