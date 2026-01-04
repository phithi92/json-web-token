<?php

declare(strict_types=1);

namespace Tests\phpunit;

use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingHeaderAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use ReflectionClass;

class JwtTokenBuilderTest extends TestCaseWithSecrets
{
    public function testMissingAlgorithmInHeaderThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('buildHeader');
        $method->setAccessible(true);

        $this->expectException(MissingHeaderAlgorithmException::class);
        $this->expectExceptionMessage('JWT header does not contain an algorithm (alg).');

        $method->invoke($builder, 'JWT', null, 'some-kid', 'A256GCM');
    }

    public function testUnresolvableKidThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $this->expectException(UnresolvableKeyException::class);
        $this->expectExceptionMessage('INVALID_KID');

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('buildHeader');
        $method->setAccessible(true);

        $method->invoke($builder, 'JWT', 'RSA-OAEP', 'INVALID_KID', 'A256GCM');
    }

    public function testInvalidHeaderConfigThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('resolveHeaderParamsFromConfig');
        $method->setAccessible(true);

        $this->expectException(InvalidAlgorithmConfigurationException::class);
        $this->expectExceptionMessage(
            'Invalid algorithm configuration: expected token_type, alg, and enc to be scalar values.'
        );

        $method->invoke($builder, [
            'token_type' => 123,
            'alg' => [],
            'enc' => null,
        ]);
    }

    public function testBuildDefaultKid(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('deriveDefaultKid');
        $method->setAccessible(true);

        $kid = $method->invoke($builder, 'RSA-OAEP', 'A256GCM');
        $this->assertSame('RSA-OAEP_A256GCM', $kid);

        $kid = $method->invoke($builder, 'dir', 'A128CBC');
        $this->assertSame('A128CBC', $kid);
    }
}
