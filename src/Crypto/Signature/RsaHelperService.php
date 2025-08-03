<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Exception;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;

class RsaHelperService
{
    /**
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private array $checkedKeys;

    private JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }

    public function mapHashToOpenSSLConstant(string $hash): int
    {
        return match (strtolower($hash)) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => throw new \InvalidArgumentException("Unsupported hash algorithm: {$hash}"),
        };
    }

    public function getRequiredRsaKeySize(string $hashAlgorithm): int
    {
        return match (strtolower($hashAlgorithm)) {
            'sha256' => 2048,
            'sha384' => 3072,
            'sha512' => 4096,
            default => throw new InvalidArgumentException("Unsupported hash algorithm: {$hashAlgorithm}"),
        };
    }

    /**
     * Validates the RSA key against the algorithm used.
     *
     * @throws InvalidSignatureException
     */
    public function assertRsaKeyIsValid(string $kid, string $algorithm, string $role): OpenSSLAsymmetricKey
    {
        $cached = $this->getCachedRsaKey($kid);
        if ($cached !== null) {
            return $cached;
        }

        if (! in_array($role, ['private', 'public'])) {
            throw new Exception('Given role is invalid.');
        }

        $key = $role === 'public' ? $this->manager->getPublicKey($kid) : $this->manager->getPrivateKey($kid);

        $details = openssl_pkey_get_details($key);

        if (
            ! is_array($details)
            || ! isset($details['rsa'])
            || ! is_array($details['rsa'])
            || ! isset($details['rsa']['n'])
            || ! is_string($details['rsa']['n'])
        ) {
            throw new InvalidSignatureException("Key [{$kid}] is not a valid RSA key.");
        }

        $modulusLength = strlen($details['rsa']['n']);
        $expectedKeySize = $this->getRequiredRsaKeySize($algorithm);
        $actualKeySize = $modulusLength * 8;
        // Bytes to bits
        if ($actualKeySize < $expectedKeySize) {
            throw new InvalidSignatureException("RSA key must be at least {$expectedKeySize} bits long");
        }

        $this->cacheRsaKeyValidation($kid, $key);

        return $key;
    }

    /**
     * @return OpenSSLAsymmetricKey|null return OpenSSLAsymmetricKey when exist, else null
     */
    public function getCachedRsaKey(string $kid): OpenSSLAsymmetricKey|null
    {
        return $this->checkedKeys[$kid] ?? null;
    }

    public function cacheRsaKeyValidation(string $kid, OpenSSLAsymmetricKey $key): void
    {
        $this->checkedKeys[$kid] = $key;
    }
}
