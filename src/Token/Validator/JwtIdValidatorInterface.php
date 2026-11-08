<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use Phithi92\JsonWebToken\Token\Serializer\JwtIdInput;

interface JwtIdValidatorInterface
{
    public function isAllowed(JwtIdInput $jwtId): bool;

    public function useAllowList(): bool;

    public function allow(JwtIdInput $jwtId, int $untilTimestamp): void;

    public function deny(JwtIdInput $jwtId, int $untilTimestamp): void;

    public function ttlFromTimestamp(int $untilTimestamp): int;
}
