<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Tests\Token\Validator;

use Phithi92\JsonWebToken\Token\Validator\RedisJwtIdValidator;
use PHPUnit\Framework\TestCase;
use Redis;
use RuntimeException;

final class RedisJwtIdValidatorTest extends TestCase
{
    public function test_isAllowed_returns_true_when_jwtId_is_null_and_allowList_disabled(): void
    {
        $redis = $this->createMock(Redis::class);

        $sut = new RedisJwtIdValidator($redis, false);

        self::assertTrue($sut->isAllowed(null));
    }

    public function test_isAllowed_returns_false_when_jwtId_is_null_and_allowList_enabled(): void
    {
        $redis = $this->createMock(Redis::class);

        $sut = new RedisJwtIdValidator($redis, true);

        self::assertFalse($sut->isAllowed(null));
    }

    public function test_isAllowed_returns_false_when_denied(): void
    {
        $redis = $this->createMock(Redis::class);
        $redis->expects(self::once())
            ->method('exists')
            ->with('jwt:deny:abc')
            ->willReturn(1);

        $sut = new RedisJwtIdValidator($redis, false);

        self::assertFalse($sut->isAllowed('abc'));
    }

    public function test_isAllowed_returns_true_when_not_denied_and_allowList_disabled(): void
    {
        $redis = $this->createMock(Redis::class);
        $redis->expects(self::once())
            ->method('exists')
            ->with('jwt:deny:abc')
            ->willReturn(0);

        $sut = new RedisJwtIdValidator($redis, false);

        self::assertTrue($sut->isAllowed('abc'));
    }

    public function test_isAllowed_returns_false_when_allowList_enabled_and_not_explicitly_allowed(): void
    {
        $redis = $this->createMock(Redis::class);

        $calls = [];
        $redis->expects(self::exactly(2))
            ->method('exists')
            ->willReturnCallback(function (string $key) use (&$calls): int {
                $calls[] = $key;

                return match ($key) {
                    'jwt:deny:abc'  => 0,
                    'jwt:allow:abc' => 0,
                    default => throw new RuntimeException('Unexpected key: ' . $key),
                };
            });

        $sut = new RedisJwtIdValidator($redis, true);

        self::assertFalse($sut->isAllowed('abc'));
        self::assertSame(['jwt:deny:abc', 'jwt:allow:abc'], $calls);
    }

    public function test_isAllowed_returns_true_when_allowList_enabled_and_explicitly_allowed(): void
    {
        $redis = $this->createMock(Redis::class);

        $calls = [];
        $redis->expects(self::exactly(2))
            ->method('exists')
            ->willReturnCallback(function (string $key) use (&$calls): int {
                $calls[] = $key;

                return match ($key) {
                    'jwt:deny:abc'  => 0,
                    'jwt:allow:abc' => 1,
                    default => throw new RuntimeException('Unexpected key: ' . $key),
                };
            });

        $sut = new RedisJwtIdValidator($redis, true);

        self::assertTrue($sut->isAllowed('abc'));
        self::assertSame(['jwt:deny:abc', 'jwt:allow:abc'], $calls);
    }

    public function test_deny_sets_expected_key_with_ttl(): void
    {
        $redis = $this->createMock(Redis::class);
        $redis->expects(self::once())
            ->method('setex')
            ->with('jwt:deny:abc', 123, '1');

        $sut = new RedisJwtIdValidator($redis, false);

        $sut->deny('abc', 123);
    }

    public function test_allow_sets_expected_key_with_ttl(): void
    {
        $redis = $this->createMock(Redis::class);
        $redis->expects(self::once())
            ->method('setex')
            ->with('jwt:allow:abc', 456, '1');

        $sut = new RedisJwtIdValidator($redis, true);

        $sut->allow('abc', 456);
    }
}
