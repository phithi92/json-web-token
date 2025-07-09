<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\Crypto\RsaHelperService;
use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Signing\SignatureComputationFailedException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

class RsaSignatureService extends SignatureService
{
    private RsaHelperService $rsaHelper;

    public function __construct(JwtAlgorithmManager $manager)
    {
        parent::__construct($manager);
        $this->rsaHelper = new RsaHelperService($manager);
    }

    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $signature = '';
        $algorithm = (string) $config['hash_algorithm'];

        $privateKey = $this->rsaHelper->assertRsaKeyIsValid($kid, $algorithm, 'private');

        $signinInput = $this->getSigningInput($bundle);
        $algorithmConst = $this->rsaHelper->mapHashToOpenSSLConstant($algorithm);

        if (! openssl_sign($signinInput, $signature, $privateKey, $algorithmConst)) {
            throw new SignatureComputationFailedException(openssl_error_string() ?: 'Signature generation failed.');
        }
        $bundle->setSignature($signature);
    }

    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $this->resolveKid($bundle, $config);
        $algorithm = (string) $config['hash_algorithm'];
        $signature = $bundle->getSignature();

        $publicKey = $this->rsaHelper->assertRsaKeyIsValid($kid, $algorithm, 'public');

        $signinInput = $bundle->getEncryption()->getAad();
        $algorithmConst = $this->rsaHelper->mapHashToOpenSSLConstant($algorithm);

        // Verify the signature using the public key and algorithm
        $verified = openssl_verify($signinInput, $signature, $publicKey, $algorithmConst);
        if ($verified !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'unknown OpenSSL error');
        }
    }
}
