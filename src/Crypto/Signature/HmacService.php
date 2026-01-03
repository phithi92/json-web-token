<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;

use function hash_equals;
use function hash_hmac;
use function strlen;
use function strtolower;

class HmacService extends SignatureService
{
    /**
     * @var array<string, bool>
     */
    private array $checkedHmacKeys;

    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $algorithm = $this->getConfiguredHashAlgorithm($config);
        $passphrase = $this->manager->getPassphrase($kid);
        $signingInput = $this->getSigningInput($bundle);

        $this->assertHmacKeyIsValid($kid, $algorithm, $passphrase);

        $signature = hash_hmac($algorithm, $signingInput, $passphrase, true);

        $bundle->setSignature(new JwtSignature($signature));
    }

    /**
     * @throws InvalidSignatureException
     */
    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $algorithm = $this->getConfiguredHashAlgorithm($config);
        $signature = (string) $bundle->getSignature();
        $aad = $bundle->getEncryption()->getAad();

        $passphrase = $this->manager->getPassphrase($kid);

        $this->assertHmacKeyIsValid($kid, $algorithm, $passphrase);

        $expectedHash = hash_hmac($algorithm, $aad, $passphrase, true);

        // Compare the expected HMAC with the provided signature using constant-time comparison
        if (! hash_equals($expectedHash, $signature)) {
            throw new InvalidSignatureException('Signature is not valid');
        }
    }

    /**
     * @throws InvalidSignatureException
     */
    private function assertHmacKeyIsValid(string $kid, string $algorithm, string $passphrase): void
    {
        $cacheKey = $kid . ':' . strtolower($algorithm);
        if (isset($this->checkedHmacKeys[$cacheKey])) {
            return;
            // Already checked
        }

        if ($passphrase === '') {
            throw new InvalidSignatureException("HMAC key for [{$kid}] is empty.");
        }

        $minLength = match (strtolower($algorithm)) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => throw new InvalidSignatureException("Unsupported hash algorithm: {$algorithm}"),
        };

        if (strlen($passphrase) < $minLength) {
            throw new InvalidSignatureException(
                "HMAC key for [{$kid}] is too short for {$algorithm}. Expected at least {$minLength} bytes."
            );
        }

        // Mark as checked
        $this->checkedHmacKeys[$cacheKey] = true;
    }
}
