<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

final class InMemoryJwtIdValidator implements JwtIdValidatorInterface
{
    /**
     * @var array<string, bool>
     */
    private array $denyList = [];

    /**
     * @var array<string, bool>|null
     */
    private ?array $allowList = null;

    /**
     * @param array<string>|null $allowList
     * @param array<string> $denyList
     */
    public function __construct(?array $allowList = null, array $denyList = [])
    {
        if ($allowList !== null) {
            $this->allowList = $this->normalizeList($allowList);
        }

        $this->denyList = $this->normalizeList($denyList);
    }

    public function isAllowed(?string $jwtId): bool
    {
        if ($jwtId === null) {
            return $this->allowList === null;
        }

        if (isset($this->denyList[$jwtId])) {
            return false;
        }

        if ($this->allowList !== null) {
            return isset($this->allowList[$jwtId]);
        }

        return true;
    }

    /**
     * @param array<string> $list
     *
     * @return array<string, bool>
     */
    private function normalizeList(array $list): array
    {
        $normalized = [];

        foreach ($list as $value) {
            $normalized[$value] = true;
        }

        return $normalized;
    }
}
