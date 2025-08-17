<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\JwtHeader;

interface JwtHeaderCodecInterface
{
    public function encode(JwtHeader $header): string;
    public function decode(string $json): JwtHeader;
}
