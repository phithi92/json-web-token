<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;

final class InMemoryJwtIdValidator implements JwtIdValidatorInterface
{
    /**
     * jwtId => expiresAt (unix timestamp)
     *
     * @var array<string, int>
     */
    private array $denyList = [];

    /**
     * jwtId => expiresAt (unix timestamp)
     *
     * @var array<string, int>
     */
    private array $allowList = [];

    private bool $useAllowList;

    /**
     * @param array<string>|null $allowList
     * @param array<string>|null $denyList
     */
    public function __construct(
        ?array $allowList = null,
        ?array $denyList = null,
        bool $useAllowList = false
    ) {
        if ($allowList !== null) {
            // default: "never expires" for preloaded lists
            $this->allowList = $this->normalizeList($allowList);
        }

        if ($denyList !== null) {
            // default: "never expires" for preloaded lists
            $this->denyList = $this->normalizeList($denyList);
        }

        $this->useAllowList = $useAllowList;
    }

    public function useAllowList(): bool
    {
        return $this->useAllowList;
    }

    public function isAllowed(JwtIdInput $jwtId): bool
    {
        $id = (string) $jwtId;

        // 1) Deny list has priority
        if (isset($this->denyList[$id])) {
            if ($this->isExpired($this->denyList[$id])) {
                unset($this->denyList[$id]);
            } else {
                return false;
            }
        }

        // 2) If not using allow-list, it's allowed (unless denied above)
        if (! $this->useAllowList) {
            return true;
        }

        // 3) Allow-list mode: must exist AND not be expired
        if (!isset($this->allowList[$id])) {
            return false;
        }

        if ($this->isExpired($this->allowList[$id])) {
            unset($this->allowList[$id]);
            return false;
        }

        return true;
    }

    public function allow(JwtIdInput $jwtId, int $ttl): void
    {
        $this->assertTtl($ttl);

        $id = (string) $jwtId;

        $this->allowList[$id] = $this->expiresAt($ttl);
        unset($this->denyList[$id]);
    }

    public function deny(JwtIdInput $jwtId, int $ttl): void
    {
        $this->assertTtl($ttl);

        $id = (string) $jwtId;

        $this->denyList[$id] = $this->expiresAt($ttl);
        unset($this->allowList[$id]);
    }

    /**
     * @param array<string> $list
     *
     * @return array<string, int>
     */
    private function normalizeList(array $list): array
    {
        // Preloaded entries never expire by default
        $normalized = [];

        foreach ($list as $value) {
            $normalized[$value] = PHP_INT_MAX;
        }

        return $normalized;
    }

    private function isExpired(int $expiresAt): bool
    {
        return $expiresAt <= time();
    }

    private function expiresAt(int $ttl): int
    {
        // ttl=0 means "expires immediately"
        return time() + $ttl;
    }

    private function assertTtl(int $ttl): void
    {
        if ($ttl < 0) {
            throw new InvalidArgumentException('TTL must be >= 0.');
        }
    }
}
