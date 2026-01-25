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
 * Supported kty values:
 * - RSA
 * - oct
 * - EC   (from JWK)
 * - OKP  (from JWK)
 *
 * References:
 * - RFC 7638 (JSON Web Key Thumbprint)
 * - RFC 7517 (JSON Web Key)
 */
final class KeyIdentifier
{
    /**
     * RFC 7638 mandates SHA-256 as the hash algorithm.
     */
    private const ALGO = 'sha256';

    /**
     * Required JWK members per kty according to RFC 7638.
     */
    private const REQUIRED_MEMBERS = [
        'RSA' => ['e', 'kty', 'n'],
        'oct' => ['k', 'kty'],
        'EC' => ['crv', 'kty', 'x', 'y'],
        'OKP' => ['crv', 'kty', 'x'],
    ];

    /**
     * Generates a RFC 7638–compliant key identifier (kid) from a PEM-encoded key.
     *
     * Currently supported:
     * - RSA (reliable via OpenSSL details)
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
     * @param array<string, mixed> $jwk Public JWK parameters
     */
    public static function fromJwk(#[SensitiveParameter] array $jwk): string
    {
        $canonicalJson = self::canonicalJwkJson($jwk);
        $digest = hash(self::ALGO, $canonicalJson, true);

        return Base64UrlEncoder::encode($digest);
    }

    /**
     * Loads a PEM-encoded OpenSSL key.
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
     * Currently supported (PEM → JWK):
     * - RSA
     *
     * @return array<string,string>
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
                'Unsupported key type for RFC 7638 kid generation from PEM. Provide a JWK for EC/OKP.'
            ),
        };
    }

    /**
     * Extracts an RSA public JWK from OpenSSL key details.
     *
     * @param array<mixed> $details
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
     * @param array<string, mixed> $jwk
     */
    private static function canonicalJwkJson(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        if (! is_string($kty) || $kty === '') {
            throw new RuntimeException('JWK is missing required "kty".');
        }

        $required = self::REQUIRED_MEMBERS[$kty] ?? null;
        if ($required === null) {
            throw new RuntimeException(
                sprintf('Unsupported kty "%s" for RFC 7638 thumbprint.', $kty)
            );
        }

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

        // Encode with standard JSON (no optional escaping flags) for maximum interop
        return JsonEncoder::encode($thumbprint, 0);
    }
}
