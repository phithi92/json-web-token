<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;
use Psr\SimpleCache\CacheInterface;

final class Psr16JwtIdValidator extends AbstractJwtIdValidator
{
    private const DENY_PREFIX = 'jwt:deny:';
    private const ALLOW_PREFIX = 'jwt:allow:';

    private CacheInterface $cache;

    private bool $useAllowList;

    public function __construct(CacheInterface $cache, bool $useAllowList = false)
    {
        $this->cache = $cache;
        $this->useAllowList = $useAllowList;
    }

    public function useAllowList(): bool
    {
        return $this->useAllowList;
    }

    public function isAllowed(JwtIdInput $jwtId): bool
    {
        if ($this->isDenied($jwtId)) {
            return false;
        }

        if ($this->useAllowList) {
            return $this->isAllowedExplicitly($jwtId);
        }

        return true;
    }

    public function allow(JwtIdInput $jwtId, int $timestamp): void
    {
        $id = (string) $jwtId;
        $ttl = $this->ttlFromTimestamp($timestamp);

        $this->cache->set(self::ALLOW_PREFIX . $id, '1', $ttl);
    }

    public function deny(JwtIdInput $jwtId, int $timestamp): void
    {
        $id = (string) $jwtId;
        $ttl = $this->ttlFromTimestamp($timestamp);

        $this->cache->set(self::DENY_PREFIX . $id, '1', $ttl);
    }

    private function isDenied(JwtIdInput $jwtId): bool
    {
        return $this->cache->has(self::DENY_PREFIX . (string) $jwtId);
    }

    private function isAllowedExplicitly(JwtIdInput $jwtId): bool
    {
        return $this->cache->has(self::ALLOW_PREFIX . (string) $jwtId);
    }
}
