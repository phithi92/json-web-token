<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Token\JwtPayload;

interface JwtPayloadCodecInterface
{
    public function encode(JwtPayload $payload): string;

    public function decode(string $json): JwtPayload;
}
