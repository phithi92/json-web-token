<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Crypto\Signature\SignatureService;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Signing\SignatureComputationFailedException;

class EcdsaService extends SignatureService
{
    /** @var string[] */
    private array $allowedAlgorithms = ['sha256', 'sha384', 'sha512'];

    /**
     *
     * @param   EncryptedJwtBundle $jwtToken
     * @param   array<string, string> $config
     * @return  void
     * @throws  SignatureComputationFailedException
     */
    public function computeSignature(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $data       = $this->getSigningInput($jwtToken);
        $privateKey = $this->manager->getPrivateKey();
        $algorithm  = $config['hash_algorithm'];
        $signature  = '';

        if (!$this->isAllowedAlgorithm($algorithm)) {
            throw new InvalidSignatureException("Unsupported hash algorithm: $algorithm");
        }

        $success = openssl_sign($data, $signature, $privateKey, $algorithm);
        if (!$success) {
            throw new SignatureComputationFailedException(openssl_error_string() ?: '');
        }

        $jwtToken->setSignature($signature);
    }

    /**
     *
     * @param   EncryptedJwtBundle $jwtToken
     * @param   array<string, string> $config
     * @return  void
     * @throws  InvalidSignatureException
     */
    public function validateSignature(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $signature  = $jwtToken->getSignature();
        $data       = $this->getSigningInput($jwtToken);
        $publicKey  = $this->manager->getPublicKey();
        $algorithm  = $config['hash_algorithm'];

        if ($signature === null) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'unknown OpenSSL error');
        }

        if (!$this->isAllowedAlgorithm($algorithm)) {
            throw new InvalidSignatureException("Unsupported hash algorithm: $algorithm");
        }

        $verified = openssl_verify($data, $signature, $publicKey, $algorithm);
        if ($verified !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'unknown OpenSSL error');
        }
    }

    /**
     * @param string|null $algo
     * @return bool
     */
    private function isAllowedAlgorithm(?string $algo): bool
    {
        return in_array(strtolower((string)$algo), $this->allowedAlgorithms, true);
    }
}
