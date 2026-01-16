<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Builder;

use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use ReflectionClass;
use Tests\phpunit\TestCaseWithSecrets;

class JwtTokenBuilderTest extends TestCaseWithSecrets
{
    public function testInvalidHeaderConfigThrowsException(): void
    {
        $builder = new JwtTokenIssuer($this->manager);

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
}
