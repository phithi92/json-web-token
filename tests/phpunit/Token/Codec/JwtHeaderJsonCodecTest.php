<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Codec;

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;

final class JwtHeaderJsonCodecTest extends TestCase
{
    private JwtHeaderJsonCodec $codec;

    protected function setUp(): void
    {
        $this->codec = new JwtHeaderJsonCodec();
    }

    public function testEncodeProducesJsonThatRepresentsHeaderArray(): void
    {
        // Arrange
        $array = [
            'alg' => 'HS256',
            'typ' => 'JWT',
            'kid' => 'test-key-1',
        ];
        $header = JwtHeader::fromArray($array);

        // Act
        $json = $this->codec->encode($header);

        // Assert
        $this->assertJson($json);
        /** @var array<string,mixed> $decoded */
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame($array, $decoded);
    }

    public function testDecodeValidJsonReturnsHydratedJwtHeader(): void
    {
        // Arrange
        $array = [
            'alg' => 'RS256',
            'typ' => 'JWT',
            'kid' => 'abc123',
        ];
        $json = json_encode($array, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Act
        $header = $this->codec->decode($json);

        // Assert
        $this->assertInstanceOf(JwtHeader::class, $header);
        $this->assertSame($array, $header->toArray());
    }

    public function testDecodeInvalidJsonThrowsJsonException(): void
    {
        // Arrange
        $invalid = '{"alg":"HS256",'; // absichtlich kaputt

        // Assert
        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage('Syntax error');

        // Act
        $this->codec->decode($invalid);
    }

    public function testEncodeStaticDelegatesToInstanceAndWorks(): void
    {
        // Arrange
        $array = ['alg' => 'HS384', 'typ' => 'JWT'];
        $header = JwtHeader::fromArray($array);

        // Act
        $jsonViaInstance = $this->codec->encode($header);
        $jsonViaStatic   = JwtHeaderJsonCodec::encodeStatic($header);

        // Assert
        $this->assertJson($jsonViaInstance);
        $this->assertJson($jsonViaStatic);
        $this->assertSame(
            json_decode($jsonViaInstance, true, 512, JSON_THROW_ON_ERROR),
            json_decode($jsonViaStatic, true, 512, JSON_THROW_ON_ERROR),
            'encodeStatic sollte dasselbe Ergebnis liefern wie encode().'
        );
    }

    public function testDecodeStaticDelegatesToInstanceAndWorks(): void
    {
        // Arrange
        $array = ['alg' => 'ES256', 'typ' => 'JWT', 'kid' => 'kid-42'];
        $json  = json_encode($array, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Act
        $headerViaInstance = $this->codec->decode($json);
        $headerViaStatic   = JwtHeaderJsonCodec::decodeStatic($json);

        // Assert
        $this->assertSame($headerViaInstance->toArray(), $headerViaStatic->toArray());
    }
}
