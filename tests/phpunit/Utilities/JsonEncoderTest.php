<?php

declare(strict_types=1);

namespace Tests\phpunit\Utilities;

use JsonException;
use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use Phithi92\JsonWebToken\Exceptions\Json\DecodingException;

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
        $this->expectException(JsonException::class);

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
}
