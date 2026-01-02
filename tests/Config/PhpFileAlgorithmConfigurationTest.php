<?php

declare(strict_types=1);

namespace Tests\phpunit\Config;

use Phithi92\JsonWebToken\Config\PhpFileAlgorithmConfiguration;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function file_put_contents;
use function unlink;

class PhpFileAlgorithmConfigurationTest extends TestCase
{
    private string $validConfigFile;
    private string $invalidConfigFile;
    private string $missingConfigFile;

    protected function setUp(): void
    {
        $this->validConfigFile = __DIR__ . '/valid_algorithms.php';
        file_put_contents(
            $this->validConfigFile,
            '<?php return ["RSA-OAEP" => ["token_type" => "JWT", "alg" => "RSA-OAEP", "enc" => "A256GCM"]];'
        );

        $this->invalidConfigFile = __DIR__ . '/invalid_algorithms.php';
        file_put_contents($this->invalidConfigFile, '<?php return "not an array";');

        $this->missingConfigFile = __DIR__ . '/missing_algorithms.php';
        @unlink($this->missingConfigFile); // ensure it's not there
    }

    protected function tearDown(): void
    {
        @unlink($this->validConfigFile);
        @unlink($this->invalidConfigFile);
    }

    public function testLoadsValidConfiguration(): void
    {
        $config = new PhpFileAlgorithmConfiguration($this->validConfigFile);

        $alg = $config->get('RSA-OAEP');

        $this->assertIsArray($alg);
        $this->assertSame('RSA-OAEP', $alg['alg']);
        $this->assertSame('A256GCM', $alg['enc']);
        $this->assertTrue($config->isSupported('RSA-OAEP'));
    }

    public function testGetReturnsEmptyArrayForUnknownAlgorithm(): void
    {
        $config = new PhpFileAlgorithmConfiguration($this->validConfigFile);

        $result = $config->get('UNKNOWN');
        $this->assertSame([], $result);
    }

    public function testIsSupportedReturnsFalseForUnknownAlgorithm(): void
    {
        $config = new PhpFileAlgorithmConfiguration($this->validConfigFile);

        $this->assertFalse($config->isSupported('FOO'));
    }

    public function testThrowsExceptionIfFileDoesNotExist(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Algorithm config file not found');

        new PhpFileAlgorithmConfiguration($this->missingConfigFile);
    }

    public function testThrowsExceptionIfFileDoesNotReturnArray(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('must return an array');

        new PhpFileAlgorithmConfiguration($this->invalidConfigFile);
    }
}
