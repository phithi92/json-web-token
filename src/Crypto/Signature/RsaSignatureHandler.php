<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtSignature;
use ValueError;

use function openssl_sign;
use function openssl_verify;

class RsaSignatureHandler extends AbstractSignatureHandler
{
    private OpenSslErrorHelper $errorHelper;

    /** @var array<string, OpenSSLAsymmetricKey> */
    private array $checkedKeys = [];

    public function __construct(JwtKeyManager $manager, ?KidResolverInterface $kidResolver = null)
    {
        parent::__construct($manager, $kidResolver);
        $this->errorHelper = new OpenSslErrorHelper();
    }

    /**
     * @param non-empty-string $kid Key identifier for the private key
     * @param non-empty-string $algorithm Signature algorithm (e.g., 'ES256', 'ES384', 'ES512')
     * @param non-empty-string $signingInput The data to be signed (JWS signing input)
     *
     * @throws SignatureComputationException
     */
    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult
    {
        try {
            $hashAlgorithm = SignatureHashAlgorithm::from($algorithm);
        } catch (ValueError) {
            throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}");
        }

        $privateKey = $this->getValidatedRsaKey($kid, $hashAlgorithm, KeyRole::Private);

        $signature = '';
        if (! openssl_sign($signingInput, $signature, $privateKey, $hashAlgorithm->name)) {
            $message = $this->errorHelper->getFormattedErrorMessage('Compute Signature Failed: ');
            throw new SignatureComputationException($message);
        }

        /** @var string $signature */
        return new SignatureHandlerResult(signature: new JwtSignature($signature));
    }

    /**
     * Validates a digital signature using RSA public key cryptography.
     *
     * Verification process:
     * 1. Validates the RSA public key and algorithm combination
     * 2. Maps the algorithm to OpenSSL constant
     * 3. Performs signature verification using openssl_verify()
     * 4. Handles verification results and OpenSSL errors appropriately
     *
     * @param non-empty-string $kid Key identifier for the public key
     * @param non-empty-string $algorithm Signature algorithm (e.g., 'RS256', 'RS384', 'RS512')
     * @param non-empty-string $aad Additional authenticated data to verify
     * @param non-empty-string $signature The signature to validate
     *
     * @throws InvalidTokenException When signature validation fails (verified = 0)
     * @throws SignatureComputationException When OpenSSL verification fails (verified = -1) or other errors occur
     * @throws CryptoException When key validation fails
     */
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        try {
            $hashAlgorithm = SignatureHashAlgorithm::from($algorithm);
        } catch (ValueError) {
            throw new InvalidTokenException("Unsupported hash algorithm: {$algorithm}");
        }

        $publicKey = $this->getValidatedRsaKey($kid, $hashAlgorithm, KeyRole::Public);

        $verified = openssl_verify($aad, $signature, $publicKey, $hashAlgorithm->name);

        $errors = $this->errorHelper->collectErrors();

        if ($verified === 1) {
            return;
        }

        if ($verified === 0) {
            throw new InvalidTokenException(
                'Validate Signature Failed: ' . implode(' | ', $errors)
            );
        }

        // $verified === -1 or anything unexpected
        $message = 'Validate Signature Failed: ';

        $message .= $errors === []
            ? 'OpenSSL verify error'
            : implode(' | ', $errors);

        throw new SignatureComputationException($message);
    }

    /**
     * Validates the RSA key against the algorithm used.
     *
     * @throws InvalidTokenException
     */
    private function getValidatedRsaKey(string $kid, SignatureHashAlgorithm $algorithm, KeyRole $role): OpenSSLAsymmetricKey
    {
        $cached = $this->getCachedRsaKey($kid, $role, $algorithm);
        if ($cached !== null) {
            return $cached;
        }

        $key = $role === KeyRole::Public ? $this->manager->getPublicKey($kid) : $this->manager->getPrivateKey($kid);

        $this->assertValidKeySize($key, $kid, $algorithm);

        $this->cacheRsaKeyValidation($kid, $role, $key, $algorithm);

        return $key;
    }

    /**
     * @return OpenSSLAsymmetricKey|null return OpenSSLAsymmetricKey when exist, else null
     */
    private function getCachedRsaKey(string $kid, KeyRole $role, SignatureHashAlgorithm $algorithm): ?OpenSSLAsymmetricKey
    {
        return $this->checkedKeys[$kid . ':' . $role->value . ':' . $algorithm->name] ?? null;
    }

    private function cacheRsaKeyValidation(string $kid, KeyRole $role, OpenSSLAsymmetricKey $key, SignatureHashAlgorithm $algorithm): void
    {
        $this->checkedKeys[$kid . ':' . $role->value . ':' . $algorithm->name] = $key;
    }

    private function assertValidKeySize(OpenSSLAsymmetricKey $key, string $kid, SignatureHashAlgorithm $algorithm): void
    {
        $keysize = $this->resolveKeySize($key, $kid);
        $actualBits = strlen($keysize) * 8;
        $expectedBits = $algorithm->rsaMinKeyBits();

        if ($actualBits < $expectedBits) {
            throw new InvalidTokenException("RSA key must be at least {$expectedBits} bits long");
        }
    }

    /**
     * Resolves the RSA key modulus (n) from the given key.
     *
     * @param OpenSSLAsymmetricKey $key The RSA key to resolve
     * @param string $kid The key identifier (for error messages)
     *
     * @return string The modulus (n) as binary string
     *
     * @throws InvalidTokenException If the key is not a valid RSA key
     */
    private function resolveKeySize(OpenSSLAsymmetricKey $key, string $kid): string
    {
        /** @var array{rsa?: array{n?: string}}|false $details */
        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['rsa']['n'])) {
            throw new InvalidTokenException("Key [{$kid}] is not a valid RSA key.");
        }

        return $details['rsa']['n'];
    }
}
