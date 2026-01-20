<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

interface JwtIdValidatorInterface
{
    public function isAllowed(?string $jwtId): bool;

    public function allow(string $jwtId, int $ttl): void;

    public function deny(string $jwtId, int $ttl): void;
}
