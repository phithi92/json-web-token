<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Config\AlgorithmConfig;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;
use Phithi92\JsonWebToken\Token\Serializer\JwsSigningInput;
use ValueError;

use function hash_equals;
use function hash_hmac;
use function sprintf;
use function strlen;
use function strtolower;

class HmacSignatureHandler extends AbstractSignatureHandler
{
    /**
     * @var array<string, bool>
     */
    private array $checkedHmacKeys;

    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        $cnf = new AlgorithmConfig($config);

        $kid = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $cnf->hashAlgorithm();
        $passphrase = $this->manager->getPassphrase($kid);

        $this->assertHmacKeyIsValid($kid, $algorithm, $passphrase);

        $signingInput = JwsSigningInput::fromBundle($bundle);

        $signature = hash_hmac($algorithm, $signingInput, $passphrase, true);

        $bundle->setSignature(new JwtSignature($signature));
    }

    /**
     * @throws InvalidTokenException
     */
    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        $cnf = new AlgorithmConfig($config);

        $kid = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $cnf->hashAlgorithm();
        $passphrase = $this->manager->getPassphrase($kid);
        $aad = $bundle->getEncryption()->getAad();

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

        $signature = (string) $bundle->getSignature();

        // Compare the expected HMAC with the provided signature using constant-time comparison
        if (! hash_equals($expectedHash, $signature)) {
            throw new InvalidTokenException('Signature is not valid');
        }
    }

    /**
     * @throws InvalidTokenException
     */
    private function assertHmacKeyIsValid(string $kid, string $algorithm, string $passphrase): void
    {
        $cacheKey = $kid . ':' . strtolower($algorithm);
        if (isset($this->checkedHmacKeys[$cacheKey])) {
            return;
            // Already checked
        }

        if ($passphrase === '') {
            throw new InvalidTokenException("HMAC key for [{$kid}] is empty.");
        }

        $minLength = match (strtolower($algorithm)) {
            'sha256' => 32,
            'sha384' => 48,
            'sha512' => 64,
            default => throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}"),
        };

        if (strlen($passphrase) < $minLength) {
            throw new InvalidTokenException(
                "HMAC key for [{$kid}] is too short for {$algorithm}. Expected at least {$minLength} bytes."
            );
        }

        // Mark as checked
        $this->checkedHmacKeys[$cacheKey] = true;
    }
}
