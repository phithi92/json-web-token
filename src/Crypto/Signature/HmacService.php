<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidSignatureException;
use Phithi92\JsonWebToken\Exceptions\Crypto\MissingPassphraseException;

class HmacService extends SignatureService
{
    public function computeSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $passphrase     = $this->manager->getPassphrase();
        $algorithm      = $config['hash_algorithm'];
        $signingInput   = $this->getSigningInput($bundle);

        $signature = hash_hmac($algorithm, $signingInput, $passphrase, true);

        $bundle->setSignature($signature);
    }

    public function validateSignature(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm  = $config['hash_algorithm'];        // e.g., 'sha256'
        $signature  = $bundle->getSignature();          // Signature from JWT
        $data       = $this->getSigningInput($bundle);  // Base64Url-encoded header.payload
        $passphrase = $this->manager->getPassphrase();  // Shared secret key

        if ($passphrase === null) {
            throw new MissingPassphraseException();
        }

        // Compute the HMAC for the input data using the configured algorithm
        $expectedHash = hash_hmac($algorithm, $data, $passphrase, true);

        // Compare the expected HMAC with the provided signature using constant-time comparison
        if (! hash_equals($expectedHash, $signature)) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'unknown OpenSSL error');
        }
    }
}
