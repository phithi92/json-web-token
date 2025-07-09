<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Crypto\Signature\SignatureService;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Signing\SignatureComputationFailedException;
use Phithi92\JsonWebToken\EncryptedJwtBundle;

class RsaSignatureService extends SignatureService
{
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm      = $config['hash_algorithm'];
        $algorithmConst = $this->mapHashToOpenSSLConstant($algorithm);
        $signinInput    = $this->getSigningInput($bundle);
        $privateKey     = $this->manager->getPrivateKey();
        $signature      = '';

        // Directly sign the data using the private key and algorithm
        if (!openssl_sign($signinInput, $signature, $privateKey, $algorithmConst)) {
            throw new SignatureComputationFailedException(openssl_error_string() ?: 'Signature generation failed.');
        }

        $bundle->setSignature($signature);
    }

    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm      = $config['hash_algorithm'];
        $algorithmConst = $this->mapHashToOpenSSLConstant($algorithm);
        $signature      = $bundle->getSignature();
        $signinInput    = $this->getSigningInput($bundle);
        $publicKey      = $this->manager->getPublicKey();

        // Verify the signature using the public key and algorithm
        $verified = openssl_verify($signinInput, $signature, $publicKey, $algorithmConst);
        if ($verified !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'unknown OpenSSL error');
        }
    }

    private function mapHashToOpenSSLConstant(string $hash): int
    {
        return match (strtolower($hash)) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default  => throw new \InvalidArgumentException("Unsupported hash algorithm: $hash"),
        };
    }
}
