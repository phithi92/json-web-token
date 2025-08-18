<?php

declare(strict_types=1);

namespace Tests\phpunit\Utilities;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Phithi92\JsonWebToken\Exceptions\Token\TokenErrorMessagesEnum;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

class EnumUtilsTest extends TestCase
{
    public function testFromNameReturnsEnumCase(): void
    {
        $case = EnumUtils::fromName(TokenErrorMessagesEnum::class, 'INVALID_SIGNATURE');
        $this->assertSame(TokenErrorMessagesEnum::INVALID_SIGNATURE, $case);
    }

    public function testFromNameInvalidCaseThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        EnumUtils::fromName(TokenErrorMessagesEnum::class, 'FOO');
    }

    public function testFromNameInvalidClassThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        EnumUtils::fromName(\stdClass::class, 'BAR');
    }
}
