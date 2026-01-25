<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;
use RuntimeException;
use SensitiveParameter;

use function hash;
use function is_array;
use function is_int;
use function is_string;
use function ksort;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function sprintf;

/**
 * Generates RFC 7638–compliant key identifiers (kid).
 *
 * A key identifier is derived as a JWK thumbprint using SHA-256 over
 * a canonical JSON representation of the required public key parameters.
 *
 * This implementation:
 * - supports RSA keys (fully)
 * - supports symmetric keys ("oct")
 * - derives the PUBLIC JWK automatically from PEM input
 *
 * References:
 * - RFC 7638 (JSON Web Key (JWK) Thumbprint)
 * - RFC 7517 (JSON Web Key)
 */
final class KeyIdentifier
{
    /**
     * RFC 7638 mandates SHA-256 as the hash algorithm.
     */
    private const ALGO = 'sha256';

    /**
     * Generates a RFC 7638–compliant key identifier (kid) from a PEM-encoded key.
     *
     * The PEM may contain either a public or a private key.
     * In both cases, the PUBLIC key parameters are derived and used.
     *
     * @param string $pem PEM-encoded public or private key
     */
    public static function fromPem(#[SensitiveParameter] string $pem): string
    {
        $key = self::loadOpenSslKey($pem);
        $jwk = self::publicJwkFromOpenSslKey($key);

        return self::fromJwk($jwk);
    }

    /**
     * Generates a RFC 7638–compliant key identifier (kid) from a symmetric secret.
     *
     * For symmetric algorithms (e.g. HS256), RFC 7638 specifies an "oct" JWK,
     * where the member "k" contains the base64url-encoded raw key bytes.
     *
     * @param string $secret Raw secret key material
     */
    public static function fromSecret(#[SensitiveParameter] string $secret): string
    {
        return self::fromJwk([
            'kty' => 'oct',
            'k' => Base64UrlEncoder::encode($secret),
        ]);
    }

    /**
     * Generates a RFC 7638–compliant key identifier (kid) from a public JWK.
     *
     * @param array<string,string> $jwk Public JWK parameters
     */
    public static function fromJwk(#[SensitiveParameter] array $jwk): string
    {
        $canonicalJson = self::canonicalJwkJson($jwk);

        // RFC 7638 requires SHA-256 over the canonical JSON representation
        $digest = hash(self::ALGO, $canonicalJson, true);

        return Base64UrlEncoder::encode($digest);
    }

    /**
     * Loads a PEM-encoded OpenSSL key.
     *
     * Accepts both private and public keys.
     *
     * @throws RuntimeException if the key cannot be loaded
     */
    private static function loadOpenSslKey(#[SensitiveParameter] string $pem): OpenSSLAsymmetricKey
    {
        $privateKey = openssl_pkey_get_private($pem);
        if ($privateKey instanceof OpenSSLAsymmetricKey) {
            return $privateKey;
        }

        $publicKey = openssl_pkey_get_public($pem);
        if ($publicKey instanceof OpenSSLAsymmetricKey) {
            return $publicKey;
        }

        throw new RuntimeException('Could not load OpenSSL key (neither private nor public).');
    }

    /**
     * Builds a PUBLIC JWK from an OpenSSL key resource.
     *
     * Only public parameters are extracted, even if the key is private.
     *
     * Currently supported:
     * - RSA (reliable via OpenSSL details)
     *
     * @return array<string,string> Public JWK
     */
    private static function publicJwkFromOpenSslKey(#[SensitiveParameter] OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ! is_int($details['type'] ?? null)) {
            throw new RuntimeException('Could not determine OpenSSL key details.');
        }

        return match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => self::rsaPublicJwkFromDetails($details),
            default => throw new RuntimeException(
                'Unsupported key type for RFC 7638 kid generation.'
            ),
        };
    }

    /**
     * Extracts an RSA public JWK from OpenSSL key details.
     *
     * Required RFC 7638 members:
     * - kty
     * - n (modulus)
     * - e (public exponent)
     *
     * @param array<mixed> $details OpenSSL key details
     *
     * @return array<string,string>
     */
    private static function rsaPublicJwkFromDetails(array $details): array
    {
        $rsa = $details['rsa'] ?? null;

        $n = is_array($rsa) ? ($rsa['n'] ?? null) : null;
        $e = is_array($rsa) ? ($rsa['e'] ?? null) : null;

        if (! is_string($n) || ! is_string($e)) {
            throw new RuntimeException('Could not extract RSA parameters (n, e).');
        }

        return [
            'kty' => 'RSA',
            'n' => Base64UrlEncoder::encode($n),
            'e' => Base64UrlEncoder::encode($e),
        ];
    }

    /**
     * Builds the canonical JSON representation required by RFC 7638.
     *
     * Steps:
     * 1. Select only the required members for the given kty
     * 2. Sort members lexicographically
     * 3. Encode as compact JSON (no whitespace)
     *
     * @param array<string,string> $jwk
     */
    private static function canonicalJwkJson(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        if (! is_string($kty) || $kty === '') {
            throw new RuntimeException('JWK is missing required "kty".');
        }

        $required = match ($kty) {
            'RSA' => ['e', 'kty', 'n'],
            'oct' => ['k', 'kty'],
            default => throw new RuntimeException(
                sprintf('Unsupported kty "%s" for RFC 7638 thumbprint.', $kty)
            ),
        };

        $thumbprint = [];
        foreach ($required as $name) {
            $value = $jwk[$name] ?? null;
            if (! is_string($value) || $value === '') {
                throw new RuntimeException(
                    sprintf('JWK is missing required member "%s" for kty "%s".', $name, $kty)
                );
            }
            $thumbprint[$name] = $value;
        }

        // RFC 7638 mandates lexicographic ordering of JSON object members
        ksort($thumbprint);

        return JsonEncoder::encode($thumbprint);
    }
}
