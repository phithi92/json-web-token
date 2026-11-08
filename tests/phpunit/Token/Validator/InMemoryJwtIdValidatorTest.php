<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Validator;

use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJtiValidator;
use PHPUnit\Framework\TestCase;

final class InMemoryJwtIdValidatorTest extends TestCase
{
    public function testAllowListModeRequiresExplicitAllow(): void
    {
        $validator = new InMemoryJtiValidator(useAllowList: true);

        $jwtId = new JwtIdInput('token-id');

        $this->assertFalse($validator->isAllowed($jwtId));

        $validator->allow($jwtId, time() + 60);

        $this->assertTrue($validator->isAllowed($jwtId));
    }

    public function testDenyOverridesAllow(): void
    {
        $validator = new InMemoryJtiValidator(useAllowList: true);

        $jwtId = new JwtIdInput('token-id');

        $validator->allow($jwtId, time() + 60);
        $validator->deny($jwtId, time() + 60);

        $this->assertFalse($validator->isAllowed($jwtId));
    }

    public function testZeroTtlExpiresImmediately(): void
    {
        $id = new JwtIdInput('token-id');
        $validator = new InMemoryJtiValidator(useAllowList: true);

        $validator->allow($id, 0);

        $this->assertFalse($validator->isAllowed($id));
    }
}
