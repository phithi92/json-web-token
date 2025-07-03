<?php

namespace Phithi92\JsonWebToken\Crypto\Cek;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidCekLength;
use Phithi92\JsonWebToken\Interfaces\ContentEncryptionKeyManagerInterface;

class DefaultCekHandler implements ContentEncryptionKeyManagerInterface
{
    public function prepareCek(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $length = (int)$config['length']; // bits
        $bytes  = intdiv($length, 8); // convert to bytes

        $cek = random_bytes($bytes);

        $jwtToken->getEncryption()->setCek($cek);
    }

    public function validateCek(EncryptedJwtBundle $jwtToken, array $config): void
    {
        $cek            = $jwtToken->getEncryption()->getCek();
        $cekLength      = strlen($cek);
        $expectedLength = (int)$config['length']; // bits
        $expectedBytes  = intdiv($expectedLength, 8); // convert to bytes

        if ($cekLength < $expectedBytes) {
            throw new InvalidCekLength($cekLength, $expectedBytes);
        }
    }
}
