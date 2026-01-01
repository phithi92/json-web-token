<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Token\SignatureComputationFailedException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

use function is_array;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_sign;
use function openssl_verify;
use function strtolower;

class EcdsaService extends SignatureService
{
    /**
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private array $checkedKeys = [];

    /**
     * Create a digital signature over the bundle using ECDSA.
     *
     * @throws SignatureComputationFailedException
     */
    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $data = $this->getSigningInput($bundle);
        $algorithm = $this->getConfiguredHashAlgorithm($config);

        $privateKey = $this->loadAndValidateEcdsaKey($kid, $algorithm, 'private');
        $signature = $this->signData($data, $privateKey, $algorithm);

        $bundle->setSignature(new JwtSignature($signature));
    }

    /**
     * Verify the bundle’s digital signature using ECDSA.
     *
     * @throws InvalidSignatureException
     */
    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);

        $signature = $bundle->getSignature();
        $data = $bundle->getEncryption()->getAad();
        $algorithm = $this->getConfiguredHashAlgorithm($config);

        $publicKey = $this->loadAndValidateEcdsaKey($kid, $algorithm, 'public');
        $this->verifySignature($data, $signature, $publicKey, $algorithm);
    }

    private function verifySignature(
        string $data,
        string $signature,
        OpenSSLAsymmetricKey $publicKey,
        string $algorithm,
    ): void {
        $verified = openssl_verify($data, $signature, $publicKey, $algorithm);
        if ($verified !== 1) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Validate Signature Failed: ');
            throw new InvalidSignatureException($message);
        }
    }

    private function signData(string $data, OpenSSLAsymmetricKey $privateKey, string $algorithm): string
    {
        /** @var string|null $signature */
        $signature = null;
        $success = openssl_sign($data, $signature, $privateKey, $algorithm);

        if ($success === false || ! is_string($signature)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Compute Signature Failed: ');
            throw new SignatureComputationFailedException($message);
        }

        return $signature;
    }

    /**
     * Load an EC key and validate its curve against the expected curve for the hash algorithm.
     *
     * @throws InvalidSignatureException
     */
    private function loadAndValidateEcdsaKey(string $kid, string $hashAlgorithm, string $role): OpenSSLAsymmetricKey
    {
        $cachedKey = $this->getCachedKey($kid);
        if ($cachedKey !== null) {
            return $cachedKey;
        }

        $key = $this->loadOpensslKey($kid, $role);

        $details = $this->extractKeyDetails($key, $kid);
        $actualCurve = $this->extractCurveNameFromKeyDetails($details, $kid);

        $this->assertValidKey($actualCurve, $hashAlgorithm, $kid);

        $this->cacheValidatedKey($kid, $key);

        return $key;
    }

    private function assertValidKey(string $actualCurve, string $hashAlgorithm, string $kid): void
    {
        $expectedCurve = $this->mapHashAlgorithmToCurve($hashAlgorithm);

        if ($actualCurve !== $expectedCurve) {
            throw new InvalidSignatureException(
                "Invalid EC curve for [{$kid}]: expected [{$expectedCurve}], got [{$actualCurve}]."
            );
        }
    }

    private function loadOpensslKey(string $kid, string $role): OpenSSLAsymmetricKey
    {
        return $role === 'public'
            ? $this->manager->getPublicKey($kid)
            : $this->manager->getPrivateKey($kid);
    }

    /**
     * @param array<mixed> $details
     *
     * @throws InvalidSignatureException
     */
    private function extractCurveNameFromKeyDetails(array $details, string $kid): string
    {
        if (! is_array($details['ec'])) {
            throw new InvalidSignatureException('Key is no valid EC key.');
        }
        $actualCurve = $details['ec']['curve_name'] ?? null;
        if (! is_string($actualCurve)) {
            throw new InvalidSignatureException("Key [{$kid}] has no valid curve name.");
        }

        return $actualCurve;
    }

    /**
     * @return array<mixed>
     *
     * @throws InvalidSignatureException
     */
    private function extractKeyDetails(OpenSSLAsymmetricKey $key, string $kid): array
    {
        $details = openssl_pkey_get_details($key);

        if (! is_array($details) || ! isset($details['ec']) || ! is_array($details['ec'])) {
            throw new InvalidSignatureException("Key [{$kid}] is not a valid EC key.");
        }

        return $details;
    }

    private function getCachedKey(string $kid): ?OpenSSLAsymmetricKey
    {
        return $this->checkedKeys[$kid] ?? null;
    }

    private function cacheValidatedKey(string $kid, OpenSSLAsymmetricKey $key): void
    {
        $this->checkedKeys[$kid] = $key;
    }

    private function mapHashAlgorithmToCurve(string $hashAlgorithm): string
    {
        return match (strtolower($hashAlgorithm)) {
            'sha256' => 'prime256v1', // ES256
            'sha384' => 'secp384r1',  // ES384
            'sha512' => 'secp521r1',  // ES512
            default => throw new InvalidSignatureException("Unsupported hash algorithm for EC key: {$hashAlgorithm}."),
        };
    }
}
