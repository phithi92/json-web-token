<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Content;

use Phithi92\JsonWebToken\Exceptions\Crypto\DecryptionException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidTokenException;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Utilities\OpenSslErrorHelper;

use function openssl_private_decrypt;
use function openssl_public_encrypt;

final class RsaEncryptionService extends ContentCryptoService
{
    /**
     * @param array<string,int|string> $config
     */
    public function decryptPayload(JwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();

        $unsealedPayload = '';
        $decrypted = openssl_private_decrypt(
            data: $bundle->getPayload()->getEncryptedPayload(),
            decrypted_data: $unsealedPayload,
            private_key: $this->manager->getPrivateKey($kid),
            padding: (int) $config['padding']
        );
        if (! $decrypted) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Decrypt Payload Failed: ');
            throw new DecryptionException($message);
        }

        /** @var string $unsealedPayload */
        JwtPayloadJsonCodec::decodeStaticInto($unsealedPayload, $bundle->getPayload());
    }

    /**
     * @param array<string,int|string> $config
     */
    public function encryptPayload(JwtBundle $bundle, array $config): void
    {
        $kid = $bundle->getHeader()->getKid();
        $sealedPayload = '';

        $encrypted = openssl_public_encrypt(
            data: JwtPayloadJsonCodec::encodeStatic($bundle->getPayload()),
            encrypted_data: $sealedPayload,
            public_key: $this->manager->getPublicKey($kid),
            padding: (int) $config['padding']
        );
        if (! $encrypted) {
            $message = OpenSslErrorHelper::getFormattedErrorMessage('Encrypt Payload Failed: ');
            throw new InvalidTokenException($message);
        }

        /** @var string $sealedPayload */
        $bundle->getPayload()->setEncryptedPayload($sealedPayload);
    }
}
