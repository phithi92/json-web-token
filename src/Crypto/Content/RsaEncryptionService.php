<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

use function openssl_private_decrypt;
use function openssl_public_encrypt;

final class RsaEncryptionService extends ContentCryptoService
{
    /**
     * @param array<string,int|string> $config
     */
    public function decryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $this->decrypt($bundle, $kid, $config);
    }

    /**
     * @param array<string,int|string> $config
     */
    public function encryptPayload(EncryptedJwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $this->encrypt($bundle, $kid, $config);
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws DecryptionException
     */
    public function decrypt(EncryptedJwtBundle $bundle, string $kid, array $config): void
    {
        $padding = (int) $config['padding'];
        $privateKey = $this->manager->getPrivateKey($kid);
        $sealedPayload = $bundle->getPayload()->getEncryptedPayload();

        $unsealedPayload = '';
        if (! openssl_private_decrypt($sealedPayload, $unsealedPayload, $privateKey, $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new DecryptionException($message);
        }

        /** @var string $unsealedPayload */
        JwtPayloadJsonCodec::decodeStaticInto($unsealedPayload, $bundle->getPayload());
    }

    /**
     * @param array<string,int|string> $config
     *
     * @throws InvalidTokenException
     */
    public function encrypt(EncryptedJwtBundle $bundle, string $kid, array $config): void
    {
        $padding = (int) $config['padding'];
        $publicKey = $this->manager->getPublicKey($kid);
        $payloadJson = JwtPayloadJsonCodec::encodeStatic($bundle->getPayload());

        $sealedPayload = '';
        if (! openssl_public_encrypt($payloadJson, $sealedPayload, $publicKey, $padding)) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        /** @var string $sealedPayload */
        $bundle->getPayload()->setEncryptedPayload($sealedPayload);
    }
}
