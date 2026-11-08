<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Tests\Token\Validator;

use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Phithi92\JsonWebToken\Token\Validator\Psr16JwtIdValidator;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use RuntimeException;

final class Psr16JwtIdValidatorTest extends TestCase
{
    public function testIsAllowedReturnsFalseWhenDenied(): void
    {
        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())
            ->method('has')
            ->with('jwt:deny:abc')
            ->willReturn(true);

        $sut = new Psr16JwtIdValidator($cache, false);

        self::assertFalse($sut->isAllowed(new JwtIdInput('abc')));
    }

    public function testIsAllowedReturnsTrueWhenNotDeniedAndAllowListDisabled(): void
    {
        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())
            ->method('has')
            ->with('jwt:deny:abc')
            ->willReturn(false);

        $sut = new Psr16JwtIdValidator($cache, false);

        self::assertTrue($sut->isAllowed(new JwtIdInput('abc')));
    }

    public function testIsAllowedReturnsFalseWhenAllowListEnabledAndNotExplicitlyAllowed(): void
    {
        $cache = $this->createMock(CacheInterface::class);

        $calls = [];
        $cache->expects(self::exactly(2))
            ->method('has')
            ->willReturnCallback(function (string $key) use (&$calls): bool {
                $calls[] = $key;

                return match ($key) {
                    'jwt:deny:abc' => false,
                    'jwt:allow:abc' => false,
                    default => throw new RuntimeException('Unexpected key: ' . $key),
                };
            });

        $sut = new Psr16JwtIdValidator($cache, true);

        self::assertFalse($sut->isAllowed(new JwtIdInput('abc')));
        self::assertSame(['jwt:deny:abc', 'jwt:allow:abc'], $calls);
    }

    public function testIsAllowedReturnsTrueWhenAllowListEnabledAndExplicitlyAllowed(): void
    {
        $cache = $this->createMock(CacheInterface::class);

        $calls = [];
        $cache->expects(self::exactly(2))
            ->method('has')
            ->willReturnCallback(function (string $key) use (&$calls): bool {
                $calls[] = $key;

                return match ($key) {
                    'jwt:deny:abc' => false,
                    'jwt:allow:abc' => true,
                    default => throw new RuntimeException('Unexpected key: ' . $key),
                };
            });

        $sut = new Psr16JwtIdValidator($cache, true);

        self::assertTrue($sut->isAllowed(new JwtIdInput('abc')));
        self::assertSame(['jwt:deny:abc', 'jwt:allow:abc'], $calls);
    }

    public function testDenySetsExpectedKeyWithTtl(): void
    {
        $expiresAt = time() + 123;

        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())
            ->method('set')
            ->with(
                'jwt:deny:abc',
                '1',
                $this->callback(function ($ttl) {
                    return $ttl <= 123 && $ttl > 0;
                })
            )
            ->willReturn(true);

        $sut = new Psr16JwtIdValidator($cache, false);

        $sut->deny(new JwtIdInput('abc'), $expiresAt);
    }

    public function testAllowSetsExpectedKeyWithTtl(): void
    {
        $expiresAt = time() + 456;

        $cache = $this->createMock(CacheInterface::class);
        $cache->expects(self::once())
            ->method('set')
            ->with(
                'jwt:allow:abc',
                '1',
                $this->callback(function ($ttl) {
                    return $ttl <= 456 && $ttl > 0;
                })
            )
            ->willReturn(true);

        $sut = new Psr16JwtIdValidator($cache, true);

        $sut->allow(new JwtIdInput('abc'), $expiresAt);
    }
}
