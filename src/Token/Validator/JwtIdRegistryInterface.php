<?php

namespace Phithi92\JsonWebToken\Token\Validator;

interface JwtIdRegistryInterface extends JwtIdValidatorInterface
{
    public function allow(string $jwtId, int $ttl): void;

    public function deny(string $jwtId, int $ttl): void;
}
