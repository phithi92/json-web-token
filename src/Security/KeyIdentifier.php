<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use SensitiveParameter;

final class KeyIdentifier
{
    /**
     * Algorithm used to hash key material when generating a stable key identifier.
     */
    private const ALGO = 'sha256';

    /**
     * Generates a key identifier from a PEM-encoded key by hashing its contents
     * and encoding the result as Base64URL.
     *
     * @param string $pem  The PEM-formatted key material.
     */
    public static function fromPem(#[SensitiveParameter] string $pem): string
    {
        return Base64UrlEncoder::encode(self::hashKey($pem));
    }

    /**
     * Generates a key identifier from a raw secret by hashing its value
     * and encoding the result as Base64URL.
     *
     * @param string $secret  The raw secret material.
     */
    public static function fromSecret(#[SensitiveParameter] string $secret): string
    {
        return Base64UrlEncoder::encode(self::hashKey($secret));
    }

    /**
     * Hashes key material using the configured algorithm.
     *
     * @param string $pem   Raw key or secret material.
     * @param string $algo  Hash algorithm to use (default: sha256).
     *
     * @return string Binary hash output.
     */
    private static function hashKey(#[SensitiveParameter] string $pem, string $algo = self::ALGO): string
    {
        return hash($algo, $pem, true);
    }
}
