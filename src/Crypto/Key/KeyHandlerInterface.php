<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Key;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;

interface KeyHandlerInterface
{
    public function __construct(JwtKeyManager $manager);

    public function unwrapKey(string $kid, string $wrappedKey, int $padding, string $hash): KeyUnwrapperHandlerResult;

    public function wrapKey(string $kid, string $cek, int $padding, string $hash): KeyWrapperHandlerResult;
}
