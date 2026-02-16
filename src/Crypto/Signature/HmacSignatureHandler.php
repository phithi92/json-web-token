<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\JwtSignature;
use ValueError;

use function hash_equals;
use function hash_hmac;
use function sprintf;
use function strlen;
use function strtolower;

class HmacSignatureHandler extends AbstractSignatureHandler
{
    /** @var array<string, bool> */
    private array $checkedHmacKeys;

    /** @var array<string,int> */
    private static array $HASH_LENGTHS = [
        'sha256' => 32,
        'sha384' => 48,
        'sha512' => 64
    ];

    /**
     * @{inherhit}
     */
    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult
    {
        $passphrase = $this->manager->getPassphrase($kid);

        $this->assertHmacKeyIsValid($kid, $algorithm, $passphrase);

        $signature = hash_hmac($algorithm, $signingInput, $passphrase, true);

        return new SignatureHandlerResult(signature: new JwtSignature($signature));
    }

    /**
     * Validates an HMAC signature against the given input data.
     *
     * Performs the following validations:
     * 1. Retrieves the passphrase for the given key identifier
     * 2. Validates the HMAC key and algorithm combination
     * 3. Computes the expected HMAC signature
     * 4. Verifies the computed signature matches the provided signature using constant-time comparison
     *
     * @param non-empty-string $kid Key identifier for the HMAC key
     * @param non-empty-string $algorithm HMAC algorithm (e.g., 'HS256', 'HS384', 'HS512')
     * @param non-empty-string $aad Additional authenticated data to verify
     * @param non-empty-string $signature The signature to validate against
     *
     * @return void
     *
     * @throws SignatureComputationException When signature computation fails
     * @throws InvalidTokenException When signature validation fails
     */
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        $passphrase = $this->manager->getPassphrase($kid);

        $this->assertHmacKeyIsValid($kid, $algorithm, $passphrase);

        try {
            // PHP 8+: hash_hmac() can throw ValueError (invalid args) OR return false (internal failure)
            $expectedHash = hash_hmac($algorithm, $aad, $passphrase, true);
        } catch (ValueError $e) {
            throw new SignatureComputationException(
                sprintf('Invalid HMAC algorithm: %s', $algorithm)
            );
        }

        if ($expectedHash === false) {
            throw new SignatureComputationException(
                sprintf('HMAC computation failed (algorithm: %s)', $algorithm)
            );
        }

        // Compare the expected HMAC with the provided signature using constant-time comparison
        if (! hash_equals($expectedHash, $signature)) {
            throw new InvalidTokenException('Signature is not valid');
        }
    }

    /**
     * @throws InvalidTokenException
     */
    private function assertHmacKeyIsValid(string $kid, string $algorithm, string $key): void
    {
        $cacheKey = $kid . ':' . strtolower($algorithm);
        if (isset($this->checkedHmacKeys[$cacheKey])) {
            return;
            // Already checked
        }

        if ($key === '') {
            throw new InvalidTokenException("HMAC key for [{$kid}] is empty.");
        }

        if (! isset(self::$HASH_LENGTHS[strtolower($algorithm)])) {
            throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}");
        }

        $minLength = self::$HASH_LENGTHS[strtolower($algorithm)];
        $keyLength = strlen($key);

        if ($keyLength < $minLength) {
            throw new InvalidTokenException(
                "HMAC key for kid [{$kid}] is too short for {$algorithm}. Expected at least {$minLength} bytes and got {$keyLength}."
            );
        }

        // Mark as checked
        $this->checkedHmacKeys[$cacheKey] = true;
    }
}
