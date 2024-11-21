<?php

use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

/**
 * Class Base64UrlEncoderTest
 *
 * Tests the functionality of the Base64UrlEncoder class.
 */
class Base64UrlEncoderTest extends TestCase
{
    /**
     * Tests the encode method for correct Base64 URL encoding.
     */
    public function testEncode()
    {
        $input = 'Hello, World!';
        $expected = 'SGVsbG8sIFdvcmxkIQ';
        
        $actual = Base64UrlEncoder::encode($input);
        $this->assertEquals($expected, $actual, 'The encoded string does not match the expected Base64 URL-safe string.');
    }

    /**
     * Tests the decode method for correct decoding of Base64 URL-safe strings.
     */
    public function testDecode()
    {
        $input = 'SGVsbG8sIFdvcmxkIQ';
        $expected = 'Hello, World!';
        
        $actual = Base64UrlEncoder::decode($input);
        $this->assertEquals($expected, $actual, 'The decoded string does not match the expected original string.');
    }

    public function testDecodeWithPadding()
    {
        // String mit tatsächlichem Padding (mit '=')
        $inputWithPadding = 'U29tZSBkYXRhCg=='; // "Some data\n" in Base64 mit Padding
        $expected = "Some data\n";
        $actual = Base64UrlEncoder::decode($inputWithPadding, true);
        $this->assertEquals($expected, $actual, 'The decoded string with explicit padding does not match the expected original string.');

        // String, bei dem Padding benötigt wird (kein explizites '=' vorhanden)
        $inputMissingPadding = 'U29tZSBkYXRhCg'; // "Some data\n" in Base64 ohne Padding
        $expected = "Some data\n";
        $actual = Base64UrlEncoder::decode($inputMissingPadding, true);
        $this->assertEquals($expected, $actual, 'The decoded string with added padding does not match the expected original string.');

        // String, der durch Base64-Kodierung explizites Padding erzeugt
        $originalInput = "Pad this";
        $encodedWithPadding = Base64UrlEncoder::encode($originalInput); // Sollte auf URL-konformes Base64 konvertieren
        $expectedDecoded = Base64UrlEncoder::decode($encodedWithPadding, true);
        $this->assertEquals($originalInput, $expectedDecoded, 'Reversible encoding and decoding with padding mismatch.');
    }

    /**
     * Tests the encode and decode methods together to ensure reversibility.
     */
    public function testEncodeDecodeReversibility()
    {
        $input = 'Sample string for testing.';
        
        $encoded = Base64UrlEncoder::encode($input);
        $decoded = Base64UrlEncoder::decode($encoded);
        
        $this->assertEquals($input, $decoded, 'The decoded string does not match the original input string.');
    }

    /**
     * Tests encoding and decoding with special characters.
     */
    public function testEncodeDecodeSpecialCharacters()
    {
        $input = 'This is a test: äöüß@€!';
        
        $encoded = Base64UrlEncoder::encode($input);
        $decoded = Base64UrlEncoder::decode($encoded);
        
        $this->assertEquals($input, $decoded, 'The decoded string with special characters does not match the original input string.');
    }

    /**
     * Tests encoding and decoding of an empty string.
     */
    public function testEncodeDecodeEmptyString()
    {
        $input = '';
        
        $encoded = Base64UrlEncoder::encode($input);
        $decoded = Base64UrlEncoder::decode($encoded);
        
        $this->assertEquals($input, $decoded, 'The decoded string for an empty input does not match the original input string.');
    }
}
