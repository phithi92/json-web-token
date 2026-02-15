<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Processor;

use Phithi92\JsonWebToken\Token\JwtBundle;

interface JwtTokenOperation
{
    public function resolveAlgorithm(JwtBundle $bundle): string;
    public function dispatchHandlers(string $algorithm, JwtBundle $jwtBundle): JwtBundle;
}
