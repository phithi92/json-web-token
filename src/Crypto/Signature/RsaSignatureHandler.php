<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Crypto\SignatureComputationException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyManagement\KidResolverInterface;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtSignature;

use function openssl_sign;
use function openssl_verify;

class RsaSignatureHandler extends AbstractSignatureHandler
{
    private OpenSslErrorHelper $errorHelper;

    /** @var array<string, OpenSSLAsymmetricKey> */
    private array $checkedKeys = [];

    /** @var array<string,int> */
    private static array $ALGORITHM_LENGTHS = [
        'sha256' => 2048,
        'sha384' => 3072,
        'sha512' => 4096,
    ];

    public function __construct(JwtKeyManager $manager, ?KidResolverInterface $kidResolver = null)
    {
        parent::__construct($manager, $kidResolver);
        $this->errorHelper = new OpenSslErrorHelper();
    }

    /**
     *
     * @param non-empty-string $kid Key identifier for the private key
     * @param non-empty-string $algorithm Signature algorithm (e.g., 'ES256', 'ES384', 'ES512')
     * @param non-empty-string $signingInput The data to be signed (JWS signing input)
     *
     * @return SignatureHandlerResult
     *
     * @throws SignatureComputationException
     */
    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult
    {
        if (! $this->isAlgorithmSupported($algorithm)) {
            throw new InvalidArgumentException("Unsupported hash algorithm: {$algorithm}");
        }

        $privateKey = $this->getValidatedRsaKey($kid, $algorithm, KeyRole::Private);

        $signature = '';
        if (! openssl_sign($signingInput, $signature, $privateKey, $algorithm)) {
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
     * @return void
     *
     * @throws InvalidTokenException When signature validation fails (verified = 0)
     * @throws SignatureComputationException When OpenSSL verification fails (verified = -1) or other errors occur
     * @throws CryptoException When key validation fails
     */
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void
    {
        if (! $this->isAlgorithmSupported($algorithm)) {
            throw new InvalidArgumentException("Unsupported hash algorithm: {$algorithm}");
        }

        $publicKey = $this->getValidatedRsaKey($kid, $algorithm, KeyRole::Public);

        $verified = openssl_verify($aad, $signature, $publicKey, $algorithm);

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
    private function getValidatedRsaKey(string $kid, string $algorithm, KeyRole $role): OpenSSLAsymmetricKey
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

    private function isAlgorithmSupported(string $algorithm): bool
    {
        return isset(self::$ALGORITHM_LENGTHS[$algorithm]);
    }

    /**
     * @return OpenSSLAsymmetricKey|null return OpenSSLAsymmetricKey when exist, else null
     */
    private function getCachedRsaKey(string $kid, KeyRole $role, string $algorithm): ?OpenSSLAsymmetricKey
    {
        return $this->checkedKeys[$kid . ':' . $role->value . ':' . strtolower($algorithm)] ?? null;
    }

    private function cacheRsaKeyValidation(string $kid, KeyRole $role, OpenSSLAsymmetricKey $key, string $algorithm): void
    {
        $this->checkedKeys[$kid . ':' . $role->value . ':' . strtolower($algorithm)] = $key;
    }

    private function assertValidKeySize(OpenSSLAsymmetricKey $key, string $kid, string $algorithm): void
    {
        $keysize = $this->resolveKeySize($key, $kid);
        $actualKeySize = strlen($keysize) * 8;
        $expectedKeySize = self::$ALGORITHM_LENGTHS[$algorithm];

        if ($actualKeySize < $expectedKeySize) {
            throw new InvalidTokenException("RSA key must be at least {$expectedKeySize} bits long");
        }
    }

    /**
     * Resolves the RSA key modulus (n) from the given key.
     *
     * @param OpenSSLAsymmetricKey $key The RSA key to resolve
     * @param string $kid The key identifier (for error messages)
     * @return string The modulus (n) as binary string
     * @throws InvalidTokenException If the key is not a valid RSA key
     */
    private function resolveKeySize(OpenSSLAsymmetricKey $key, string $kid): string
    {
        /** @var array{rsa?: array{n?: string}}|false $details */
        $details = openssl_pkey_get_details($key);

        if ($details === false || !isset($details['rsa']['n'])) {
            throw new InvalidTokenException("Key [{$kid}] is not a valid RSA key.");
        }

        return $details['rsa']['n'];
    }
}
