<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\EncryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

use function openssl_decrypt;
use function openssl_encrypt;
use function sprintf;

/**
 * AES-GCM implementation for JWE content encryption (RFC 7516 §5.3).
 *
 * This service performs authenticated encryption and decryption
 * of JWT payloads using AES in Galois/Counter Mode (GCM), as specified
 * in the JSON Web Encryption (JWE) standard.
 */
final class AesGcmService extends ContentCryptoService
{
    private const OPENSSL_OPTIONS = OPENSSL_RAW_DATA;

    private const AUTH_TAG_LENGTH = 16;

    /**
     * @throws InvalidTokenException
     */
    public function decryptPayload(JwtBundle $bundle, array $config): void
    {
        $unsealedPayload = openssl_decrypt(
            data: $bundle->getPayload()->getEncryptedPayload(),
            cipher_algo: $this->buildAesGcmAlgorithm($config),
            passphrase: $this->resolveCek($bundle),
            options: self::OPENSSL_OPTIONS,
            iv: $bundle->getEncryption()->getIv(),
            tag: $bundle->getEncryption()->getAuthTag(),
            aad: $bundle->getEncryption()->getAad(),
        );

        if ($unsealedPayload === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        JwtPayloadJsonCodec::decodeStaticInto($unsealedPayload, $bundle->getPayload());
    }

    public function encryptPayload(JwtBundle $bundle, array $config): void
    {
        $authTag = '';

        $sealedPayload = openssl_encrypt(
            data: JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()),
            cipher_algo: $this->buildAesGcmAlgorithm($config),
            passphrase: $this->resolveCek($bundle),
            options: self::OPENSSL_OPTIONS,
            iv: $bundle->getEncryption()->getIv(),
            tag: $authTag,
            aad: $bundle->getEncryption()->getAad(),
            tag_length: self::AUTH_TAG_LENGTH
        );

        if ($sealedPayload === false) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new EncryptionException($message);
        }

        $bundle->getPayload()->setEncryptedPayload($sealedPayload);
        $bundle->setEncryption($bundle->getEncryption()->withAuthTag($authTag));
    }

    private function resolveCek(JwtBundle $bundle): string
    {
        if ($bundle->getHeader()->getAlgorithm() === 'dir') {
            return $this->manager->getPassphrase($bundle->getHeader()->getKid());
        }

        return $bundle->getEncryption()->getCek();
    }

    /**
     * @param array<string,int|string> $config
     */
    private function buildAesGcmAlgorithm(array $config): string
    {
        /** @var int $bits */
        $bits = $config['length'];

        return sprintf('aes-%s-gcm', $bits);
    }
}
