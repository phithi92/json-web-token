<?php

namespace Phithi92\JsonWebToken\Crypto\Cek;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionKeyManagerInterface;

/**
 * Description of CbcHmacCekHandler
 *
 * @author phillipthiele
 */
class CbcHmacCekHandler implements ContentEncryptionKeyManagerInterface
{
    public function prepareCek(EncryptedJwtBundle $bundle, array $config): void
    {
        $length = (int)$config['length']; // bits
        $cek = random_bytes($lengthInBits / 8); // z. B. 512 bits für A256CBC-HS512

        $bundle->getEncryption()->setCek($cek);
    }

    public function validateCek(string $cek, int $expectedLengthBits): void
    {
        if (strlen($cek) * 8 !== $expectedLengthBits) {
            throw new InvalidAsymmetricKeyLength(strlen($cek), $expectedLengthBits);
        }
    }

    public function split(string $cek): array
    {
        $half = strlen($cek) / 2;
        return [
            'mac_key' => substr($cek, 0, $half),
            'enc_key' => substr($cek, $half),
        ];
    }
}
