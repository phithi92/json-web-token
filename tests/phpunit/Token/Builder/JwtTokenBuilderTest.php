<?php

declare(strict_types=1);

namespace Tests\phpunit;

use LogicException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use ReflectionClass;
use UnexpectedValueException;

class JwtTokenBuilderTest extends TestCaseWithSecrets
{
    public function testMissingAlgorithmInHeaderThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('createHeader');
        $method->setAccessible(true);

        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Incomplete token header configuration');

        $method->invoke($builder, 'JWT', null, 'some-kid', 'A256GCM');
    }

    public function testUnresolvableKidThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $this->expectException(UnresolvableKeyException::class);
        $this->expectExceptionMessage('INVALID_KID');

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('createHeader');
        $method->setAccessible(true);

        $method->invoke($builder, 'JWT', 'RSA-OAEP', 'INVALID_KID', 'A256GCM');
    }

    public function testInvalidHeaderConfigThrowsLogicException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('extractHeaderParams');
        $method->setAccessible(true);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Invalid header configuration');

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
        $method = $reflection->getMethod('buildDefaultKid');
        $method->setAccessible(true);

        $kid = $method->invoke($builder, 'RSA-OAEP', 'A256GCM');
        $this->assertSame('RSA-OAEP_A256GCM', $kid);

        $kid = $method->invoke($builder, 'dir', 'A128CBC');
        $this->assertSame('A128CBC', $kid);
    }
}
