<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

/**
 * AES-GCM implementation for JWE content encryption (RFC 7516 §5.3).
 *
 * This service performs authenticated encryption and decryption
 * of JWT payloads using AES in Galois/Counter Mode (GCM), as specified
 * in the JSON Web Encryption (JWE) standard.
 */
final class AesGcmService extends ContentCryptoService
{
    protected const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;

    /**
     * @throws InvalidTokenException
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm = $this->buildAlgorithmNameFromKeyLength($config);

        [$cek,$iv,$ciphertext,$authTag,$aad] = $this->extractTokenDecryptionComponents($bundle);

        $plaintext = $this->decrypt(
            $algorithm,
            self::OPENSSL_OPTIONS,
            $ciphertext,
            $cek,
            $iv,
            $authTag,
            $aad
        );

        $bundle->getPayload()->fromJson($plaintext);
    }

    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm = $this->buildAlgorithmNameFromKeyLength($config);

        [$cek,$iv,$plaintext,$aad] = $this->extractTokenEncryptionComponents($bundle);

        [$encrypted, $authTag] = $this->encrypt(
            $algorithm,
            self::OPENSSL_OPTIONS,
            $plaintext,
            $cek,
            $iv,
            $aad
        );

        $bundle->getPayload()->setEncryptedPayload($encrypted);
        $bundle->getEncryption()->setAuthTag($authTag);
    }

    /**
     * @param array<string,int|string> $config
     */
    private function buildAlgorithmNameFromKeyLength(array $config): string
    {
        /** @var int $bits */
        $bits = $config['length'];
        return sprintf('aes-%s-gcm', $bits);
    }

    /**
     * @return array{string,string,string,string,string}
     */
    private function extractTokenDecryptionComponents(EncryptedJwtBundle $bundle): array
    {
        return [
            $bundle->getEncryption()->getCek(),
            $bundle->getEncryption()->getIv(),
            $bundle->getPayload()->getEncryptedPayload(),
            $bundle->getEncryption()->getAuthTag(),
            $bundle->getEncryption()->getAad(),
        ];
    }

    /**
     * @return array{string,string,string,string}
     */
    private function extractTokenEncryptionComponents(EncryptedJwtBundle $bundle): array
    {
        return [
            $bundle->getEncryption()->getCek(),
            $bundle->getEncryption()->getIv(),
            $bundle->getPayload()->toJson(),
            Base64UrlEncoder::encode($bundle->getHeader()->toJson()),
        ];
    }

    /**
     * @throws InvalidTokenException
     */
    private function decrypt(
        string $algorithm,
        int $options,
        string $ciphertext,
        string $cek,
        string $iv,
        string $authTag,
        string $aad
    ): string {
        $plaintext = openssl_decrypt(
            $ciphertext,
            $algorithm,
            $cek,
            $options,
            $iv,
            $authTag,
            $aad
        );

        if ($plaintext === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        return $plaintext;
    }

    /**
     * @return array{string,string}
     *
     * @throws EncryptionException
     */
    private function encrypt(
        string $algorithm,
        int $options,
        string $plaintext,
        string $cek,
        string $iv,
        string $aad
    ): array {
        $authTag = '';
        $encrypted = openssl_encrypt(
            $plaintext,
            $algorithm,
            $cek,
            $options,
            $iv,
            $authTag,
            $aad
        );

        if ($encrypted === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new EncryptionException($message);
        }

        /** @var string $authTag */
        return [$encrypted,$authTag];
    }
}
