<?php

declare(strict_types=1);

namespace Tests\phpunit\Utilities;

use JsonSerializable;
use Phithi92\JsonWebToken\Exceptions\Json\EncodingException;
use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Phithi92\JsonWebToken\Exceptions\Json\DecodingException;
use Phithi92\JsonWebToken\Exceptions\Json\InvalidDepthException;

class JsonEncoderTest extends TestCase
{
    public function testEncodeValidArray(): void
    {
        $data = ['key' => 'value'];
        $json = JsonEncoder::encode($data);

        $this->assertJson($json);
        $this->assertEquals('{"key":"value"}', $json);
    }

    public function testEncodeThrowsEncodingException(): void
    {
        $this->expectException(EncodingException::class);

        // Create an array with a value that cannot be JSON encoded
        $data = ['key' => "\xB1\x31"];
        JsonEncoder::encode($data);
    }

    public function testDecodeValidJsonToArray(): void
    {
        $json = '{"key":"value"}';
        $data = JsonEncoder::decode($json, true);

        $this->assertIsArray($data);
        $this->assertArrayHasKey('key', $data);
        $this->assertEquals('value', $data['key']);
    }

    public function testDecodeValidJsonToObject(): void
    {
        $json = '{"key":"value"}';

        $data = JsonEncoder::decode($json, false);

        $this->assertIsObject($data);
        $this->assertEquals('value', $data->key);
    }

    public function testDecodeThrowsDecodingException(): void
    {
        $this->expectException(DecodingException::class);

        // Provide invalid JSON
        $invalidJson = '{"key":"value"';
        JsonEncoder::decode($invalidJson);
    }

    public function testEncodeWithCustomOptions(): void
    {
        $data = ['key' => 'value', 'special' => 'ü'];
        $json = JsonEncoder::encode($data, JSON_UNESCAPED_UNICODE);

        $this->assertEquals('{"key":"value","special":"ü"}', $json);
    }

    public function testDecodeWithCustomOptions(): void
    {
        $json = '{"key":12345678901234567890}';
        $data = JsonEncoder::decode($json, true, JSON_BIGINT_AS_STRING);

        $this->assertIsArray($data);
        $this->assertEquals('12345678901234567890', $data['key']);
    }

    public function testEncodeJsonSerializableObject(): void
    {
        $data = new class () implements JsonSerializable {
            public function jsonSerialize(): array
            {
                return ['foo' => 'bar'];
            }
        };

        $json = JsonEncoder::encode($data);
        $this->assertSame('{"foo":"bar"}', $json);
    }

    public function testDecodeWithInvalidDepthThrowsException(): void
    {
        $this->expectException(InvalidDepthException::class);

        JsonEncoder::decode('{}', true, 0, 0);
    }

    public function testEncodeWithInvalidDepthThrowsException(): void
    {
        $this->expectException(InvalidDepthException::class);

        JsonEncoder::encode(['a' => 'b'], JSON_UNESCAPED_UNICODE, 0);
    }
}
