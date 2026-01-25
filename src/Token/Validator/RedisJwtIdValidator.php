<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use Redis;

final class RedisJwtIdValidator implements JwtIdValidatorInterface
{
    private const DENY_PREFIX = 'jwt:deny:';
    private const ALLOW_PREFIX = 'jwt:allow:';

    private Redis $redis;

    private bool $useAllowList;

    public function __construct(Redis $redis, bool $useAllowList = false)
    {
        $this->redis = $redis;
        $this->useAllowList = $useAllowList;
    }

    public function isAllowed(?string $jwtId): bool
    {
        if ($jwtId === null) {
            return ! $this->useAllowList;
        }

        if ($this->isDenied($jwtId)) {
            return false;
        }

        if ($this->useAllowList) {
            return $this->isAllowedExplicitly($jwtId);
        }

        return true;
    }

    public function deny(string $jwtId, int $ttl): void
    {
        $this->redis->setex(
            self::DENY_PREFIX . $jwtId,
            $ttl,
            '1'
        );
    }

    public function allow(string $jwtId, int $ttl): void
    {
        $this->redis->setex(
            self::ALLOW_PREFIX . $jwtId,
            $ttl,
            '1'
        );
    }

    private function isDenied(string $jwtId): bool
    {
        return $this->redis->exists(self::DENY_PREFIX . $jwtId) === 1;
    }

    private function isAllowedExplicitly(string $jwtId): bool
    {
        return $this->redis->exists(self::ALLOW_PREFIX . $jwtId) === 1;
    }
}
