<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use SensitiveParameter;
use Stringable;

/**
 * Immutable value object representing a JWT signature.
 *
 * Encapsulates the raw signature string and provides a safe,
 * type-safe way to pass JWT signatures through the system.
 */
final class JwtSignature implements Stringable
{
    /**
     * The raw JWT signature.
     */
    private readonly string $value;

    /**
     * Creates a new JWT signature value object.
     *
     * @param string $signature The raw JWT signature value.
     */
    public function __construct(
        #[SensitiveParameter]
        string $signature
    ) {
        $this->value = $signature;
    }

    /**
     * Returns the signature as a string.
     */
    #[\Override]
    public function __toString(): string
    {
        return $this->value;
    }
}