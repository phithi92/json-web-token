<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializeVectorException;

interface InitializationVectorManagerInterface
{
    /**
     * Prepares or generates the Initialization Vector (IV)
     * and attaches it to the given JWT encryption bundle.
     *
     * @param EncryptedJwtBundle                          $bundle The bundle to update with a generated IV.
     * @param array<string, array<string, string>|string> $config
     *          Configuration array (expects 'length' in bits).
     */
    public function prepareIv(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * Validates the IV stored in the JWT encryption bundle against the expected length.
     *
     * @param EncryptedJwtBundle    $bundle The bundle containing the IV to validate.
     * @param array<string, string> $config
     *          Configuration array (expects 'length' in bits).
     *
     * @throws InvalidInitializeVectorException If the IV is missing or has incorrect length.
     */
    public function validateIv(EncryptedJwtBundle $bundle, array $config): void;
}
