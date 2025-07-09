<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Signing\SignatureComputationFailedException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;

class EcdsaService extends SignatureService
{
    /** @var array<string, OpenSSLAsymmetricKey> */
    private array $checkedKeys = [];

    /**
     * @param array<string, string> $config
     *
     * @throws SignatureComputationFailedException|InvalidSignatureException
     */
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $data = $this->getSigningInput($bundle);
        $algorithm = strtolower($config['hash_algorithm'] ?? '');

        $privateKey = $this->assertEcdsaKeyIsValid($kid, $algorithm, 'private');

        $success = openssl_sign($data, $signature, $privateKey, $algorithm);
        if (! $success) {
            throw new SignatureComputationFailedException(openssl_error_string() ?: 'Failed to compute ECDSA signature.');
        }

        $bundle->setSignature($signature);
    }

    /**
     * @param array<string, string> $config
     *
     * @throws InvalidSignatureException
     */
    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);

        $signature = $bundle->getSignature();
        if (! $signature) {
            throw new InvalidSignatureException('Missing signature for validation.');
        }

        $data = $bundle->getEncryption()->getAad();
        $algorithm = $config['hash_algorithm'];

        $publicKey = $this->assertEcdsaKeyIsValid($kid, $algorithm, 'public');

        $verified = openssl_verify($data, $signature, $publicKey, $algorithm);
        if ($verified !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'Signature verification failed.');
        }
    }

    /**
     * Validates the EC key curve against the algorithm and caches the result.
     *
     * @param callable(): OpenSSLAsymmetricKey $keyGenerator
     *
     * @throws InvalidSignatureException
     */
    private function assertEcdsaKeyIsValid(string $kid, string $hashAlgorithm, string $role): OpenSSLAsymmetricKey
    {
        $cachedKey = $this->getCachedEcdsaKey($kid);
        if ($cachedKey !== null) {
            return $cachedKey;
        }

        $expectedCurve = $this->resolveExpectedCurve($hashAlgorithm);

        $key = $role === 'public' ?
            $this->manager->getPublicKey($kid) :
            $this->manager->getPrivateKey($kid);

        $details = openssl_pkey_get_details($key);
        $actualCurve = $details['ec']['curve_name'] ?? null;

        if (! $actualCurve) {
            throw new InvalidSignatureException("Key [{$kid}] is not a valid EC key.");
        }

        if ($actualCurve !== $expectedCurve) {
            throw new InvalidSignatureException("Invalid EC curve for [{$kid}]: expected [{$expectedCurve}], got [{$actualCurve}].");
        }

        $this->cacheEcdsaKeyValidation($kid, $key);

        return $key;
    }

    private function getCachedEcdsaKey(string $kid): ?OpenSSLAsymmetricKey
    {
        return $this->checkedKeys[$kid] ?? null;
    }

    private function cacheEcdsaKeyValidation(string $kid, OpenSSLAsymmetricKey $key): void
    {
        $this->checkedKeys[$kid] = $key;
    }

    private function resolveExpectedCurve(string $hashAlgorithm): string
    {
        return match (strtolower($hashAlgorithm)) {
            'sha256' => 'prime256v1',  // ES256
            'sha384' => 'secp384r1',   // ES384
            'sha512' => 'secp521r1',   // ES512
            default => throw new InvalidSignatureException("Unsupported hash algorithm for EC key: {$hashAlgorithm}."),
        };
    }
}
