<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Validator;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use PHPUnit\Framework\TestCase;

final class InMemoryJwtIdValidatorTest extends TestCase
{
    public function testAllowListModeRequiresExplicitAllow(): void
    {
        $validator = new InMemoryJwtIdValidator(useAllowList: true);

        $jwtId = new JwtIdInput('token-id');

        $this->assertFalse($validator->isAllowed($jwtId));

        $validator->allow($jwtId, 60);

        $this->assertTrue($validator->isAllowed($jwtId));
    }

    public function testDenyOverridesAllow(): void
    {
        $validator = new InMemoryJwtIdValidator(useAllowList: true);

        $jwtId = new JwtIdInput('token-id');

        $validator->allow($jwtId, 60);
        $validator->deny($jwtId, 60);

        $this->assertFalse($validator->isAllowed($jwtId));
    }

    public function testNegativeTtlThrows(): void
    {
        $validator = new InMemoryJwtIdValidator();

        $this->expectException(InvalidArgumentException::class);
        $validator->allow(new JwtIdInput('token-id'), -1);
    }

    public function testZeroTtlExpiresImmediately(): void
    {
        $id = new JwtIdInput('token-id');
        $validator = new InMemoryJwtIdValidator(useAllowList: true);

        $validator->allow($id, 0);

        $this->assertFalse($validator->isAllowed($id));
    }
}
