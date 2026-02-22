<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Builder;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenIssuer;
use ReflectionClass;
use Tests\phpunit\TestCaseWithSecrets;

class JwtTokenIssuerTest extends TestCaseWithSecrets
{
    public function testInvalidHeaderConfigThrowsException(): void
    {
        $builder = new JwtTokenIssuer($this->manager);

        $reflection = new ReflectionClass($builder);
        $method = $reflection->getMethod('resolveHeaderParamsFromConfig');
        $method->setAccessible(true);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'Unsupported JWT type: %s',
            123
        ));

        $method->invoke($builder, [
            'token_type' => 123,
            'alg' => [],
            'enc' => null,
        ]);
    }
}
