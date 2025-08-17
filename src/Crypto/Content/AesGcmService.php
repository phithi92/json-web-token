<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
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

        [$cek, $iv, $sealedPayload, $authTag, $aad] = $this->extractTokenDecryptionComponents($bundle);

        $unsealedPayload = $this->decrypt(
            $algorithm,
            self::OPENSSL_OPTIONS,
            $sealedPayload,
            $cek,
            $iv,
            $authTag,
            $aad
        );

        JwtPayloadJsonCodec::decodeStaticInto($unsealedPayload, $bundle->getPayload());
    }

    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $algorithm = $this->buildAlgorithmNameFromKeyLength($config);

        [$cek, $iv, $jsonPayload, $aad] = $this->extractTokenEncryptionComponents($bundle);

        [$sealedPayload, $authTag] = $this->encrypt(
            $algorithm,
            self::OPENSSL_OPTIONS,
            $jsonPayload,
            $cek,
            $iv,
            $aad
        );

        $bundle->getPayload()->setEncryptedPayload($sealedPayload);
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
            JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()),
            Base64UrlEncoder::encode(JwtHeaderJsonCodec::encodeStatic($bundle->getHeader())),
        ];
    }

    /**
     * @throws InvalidTokenException
     */
    private function decrypt(
        string $algorithm,
        int $options,
        string $sealedPayload,
        string $cek,
        string $iv,
        string $authTag,
        string $aad
    ): string {
        $unsealedPayload = openssl_decrypt(
            $sealedPayload,
            $algorithm,
            $cek,
            $options,
            $iv,
            $authTag,
            $aad
        );

        if ($unsealedPayload === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        return $unsealedPayload;
    }

    /**
     * @return array{string,string}
     *
     * @throws EncryptionException
     */
    private function encrypt(
        string $algorithm,
        int $options,
        string $jsonPayload,
        string $cek,
        string $iv,
        string $aad
    ): array {
        $authTag = '';
        $sealedPayload = openssl_encrypt(
            $jsonPayload,
            $algorithm,
            $cek,
            $options,
            $iv,
            $authTag,
            $aad
        );

        if ($sealedPayload === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new EncryptionException($message);
        }

        /** @var string $authTag */
        return [$sealedPayload, $authTag];
    }
}
