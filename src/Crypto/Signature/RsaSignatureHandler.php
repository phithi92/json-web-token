<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Phithi92\JsonWebToken\Crypto\OpenSsl\OpenSslErrorHelper;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Exceptions\Token\SignatureComputationFailedException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Security\KeyRole;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtSignature;

use function openssl_sign;
use function openssl_verify;

class RsaSignatureHandler extends AbstractSignatureHandler
{
    /**
     * @var array<string, OpenSSLAsymmetricKey>
     */
    private array $checkedKeys = [];

    public function __construct(JwtKeyManager $manager)
    {
        parent::__construct($manager);
    }

    public function computeSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $this->getConfiguredHashAlgorithm($config);

        $privateKey = $this->assertRsaKeyIsValid($kid, $algorithm, KeyRole::Private);

        $signinInput = $this->getSigningInput($bundle);
        $algorithmConst = $this->mapHashToOpenSSLConstant($algorithm);

        $signature = '';
        if (! openssl_sign($signinInput, $signature, $privateKey, $algorithmConst)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Compute Signature Failed: ');
            throw new SignatureComputationFailedException($message);
        }

        /** @var string $signature */
        $bundle->setSignature(new JwtSignature($signature));
    }

    public function validateSignature(JwtBundle $bundle, array $config): void
    {
        $kid = $this->kidResolver->resolve($bundle, $config);
        $algorithm = $this->getConfiguredHashAlgorithm($config);
        $signature = (string) $bundle->getSignature();

        $publicKey = $this->assertRsaKeyIsValid($kid, $algorithm, KeyRole::Public);

        $signinInput = $bundle->getEncryption()->getAad();
        $algorithmConst = $this->mapHashToOpenSSLConstant($algorithm);

        // Verify the signature using the public key and algorithm
        $verified = openssl_verify($signinInput, $signature, $publicKey, $algorithmConst);
        if ($verified !== 1) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Validate Signature Failed: ');
            throw new InvalidTokenException($message);
        }
    }

    public function mapHashToOpenSSLConstant(string $hash): int
    {
        return match (strtolower($hash)) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => throw new InvalidArgumentException("Unsupported hash algorithm: {$hash}"),
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
    public function assertRsaKeyIsValid(string $kid, string $algorithm, KeyRole $role): OpenSSLAsymmetricKey
    {
        $cached = $this->getCachedRsaKey($kid);
        if ($cached !== null) {
            return $cached;
        }

        $key = $role === KeyRole::Public ? $this->manager->getPublicKey($kid) : $this->manager->getPrivateKey($kid);

        $this->assertValidKeySize($key, $kid, $algorithm);

        $this->cacheRsaKeyValidation($kid, $key);

        return $key;
    }

    /**
     * @return OpenSSLAsymmetricKey|null return OpenSSLAsymmetricKey when exist, else null
     */
    private function getCachedRsaKey(string $kid): ?OpenSSLAsymmetricKey
    {
        return $this->checkedKeys[$kid] ?? null;
    }

    private function cacheRsaKeyValidation(string $kid, OpenSSLAsymmetricKey $key): void
    {
        $this->checkedKeys[$kid] = $key;
    }

    private function assertValidKeySize(OpenSSLAsymmetricKey $key, string $kid, string $algorithm): void
    {
        $keysize = $this->getValidatedKeySize($key, $kid);

        $modulusLength = strlen($keysize);
        $expectedKeySize = $this->getRequiredRsaKeySize($algorithm);
        $actualKeySize = $modulusLength * 8;
        // Bytes to bits
        if ($actualKeySize < $expectedKeySize) {
            throw new InvalidSignatureException("RSA key must be at least {$expectedKeySize} bits long");
        }
    }

    /**
     * @throws InvalidSignatureException
     */
    private function getValidatedKeySize(OpenSSLAsymmetricKey $key, string $kid): string
    {
        /** @var array{rsa: array{n: string}}|false $details */
        $details = openssl_pkey_get_details($key);

        if ($details === false) {
            throw new InvalidSignatureException("Key [{$kid}] is not a valid RSA key.");
        }

        return $details['rsa']['n'];
    }
}
