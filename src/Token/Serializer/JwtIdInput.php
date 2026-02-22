<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Serializer;

use InvalidArgumentException;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function random_bytes;

final class JwtIdInput
{
    private readonly string $value;

    public function __construct(?string $value = null)
    {
        $normalized = $value === null ? self::generate() : $value;

        if ($normalized === '') {
            throw new InvalidArgumentException('JWT ID must not be empty.');
        }

        $this->value = $normalized;
    }

    public function __toString(): string
    {
        return $this->value;
    }

    public static function random(int $bytes = 16): self
    {
        return new self(self::generate($bytes));
    }

    public static function generate(int $bytes = 16): string
    {
        if ($bytes < 1) {
            throw new InvalidArgumentException('Byte length must be greater than 0.');
        }

        return Base64UrlEncoder::encode(bin2hex(random_bytes($bytes)));
    }
}
