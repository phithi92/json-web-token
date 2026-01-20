<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Validator;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Token\Validator\InMemoryJwtIdValidator;
use PHPUnit\Framework\TestCase;

final class InMemoryJwtIdValidatorTest extends TestCase
{
    public function testAllowListModeRequiresExplicitAllow(): void
    {
        $validator = new InMemoryJwtIdValidator(useAllowList: true);

        $this->assertFalse($validator->isAllowed('token-id'));

        $validator->allow('token-id', 60);

        $this->assertTrue($validator->isAllowed('token-id'));
    }

    public function testDenyOverridesAllow(): void
    {
        $validator = new InMemoryJwtIdValidator(useAllowList: true);

        $validator->allow('token-id', 60);
        $validator->deny('token-id', 60);

        $this->assertFalse($validator->isAllowed('token-id'));
    }

    public function testNegativeTtlThrows(): void
    {
        $validator = new InMemoryJwtIdValidator();

        $this->expectException(InvalidArgumentException::class);
        $validator->allow('token-id', -1);
    }
}
