<?php

declare(strict_types=1);

namespace Tests\phpunit;

use LogicException;
use Phithi92\JsonWebToken\Token\Builder\JwtTokenBuilder;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Tests\phpunit\TestCaseWithSecrets;

class JwtTokenBuilderTest extends TestCaseWithSecrets
{
    public function testCreateFromBundleValidatesGivenBundle(): void
    {
        $header = (new JwtHeader())
            ->setType('JWT')
            ->setAlgorithm('RSA-OAEP')
            ->setEnc('A256GCM')
            ->setKid('RSA-OAEP_A256GCM');

        $bundle = new EncryptedJwtBundle($header, new JwtPayload());

        $builder = new JwtTokenBuilder($this->manager);
        $validator = $this->createMock(JwtValidator::class);

        $validator->expects($this->once())->method('assertValidBundle');

        $builder->createFromBundle($bundle, null, $validator);
    }

    public function testMissingAlgorithmInHeaderThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new \ReflectionClass($builder);
        $method = $reflection->getMethod('createHeader');
        $method->setAccessible(true);

        $this->expectException(InvalidFormatException::class);
        $this->expectExceptionMessage('Incomplete token header configuration');

        $method->invoke($builder, 'JWT', null, 'some-kid', 'A256GCM');
    }

    public function testUnresolvableKidThrowsException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $this->expectException(UnresolvableKeyException::class);
        $this->expectExceptionMessage('INVALID_KID');

        $reflection = new \ReflectionClass($builder);
        $method = $reflection->getMethod('createHeader');
        $method->setAccessible(true);

        $method->invoke($builder, 'JWT', 'RSA-OAEP', 'INVALID_KID', 'A256GCM');
    }

    public function testInvalidHeaderConfigThrowsLogicException(): void
    {
        $builder = new JwtTokenBuilder($this->manager);

        $reflection = new \ReflectionClass($builder);
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

        $reflection = new \ReflectionClass($builder);
        $method = $reflection->getMethod('buildDefaultKid');
        $method->setAccessible(true);

        $kid = $method->invoke($builder, 'RSA-OAEP', 'A256GCM');
        $this->assertSame('RSA-OAEP_A256GCM', $kid);

        $kid = $method->invoke($builder, 'dir', 'A128CBC');
        $this->assertSame('A128CBC', $kid);
    }
}
