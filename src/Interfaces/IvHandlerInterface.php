<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Interfaces;

use Phithi92\JsonWebToken\Exceptions\Crypto\InvalidInitializationVectorException;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;

interface IvHandlerInterface
{
    /**
     * Prepares or generates the Initialization Vector (IV)
     * and attaches it to the given JWT encryption bundle.
     *
     * @param EncryptedJwtBundle                            $bundle the bundle to update with a generated IV
     * @param array<string,string|int|class-string<object>> $config
     *                                                              Configuration array (expects 'length' in bits)
     */
    public function initializeIv(EncryptedJwtBundle $bundle, array $config): void;

    /**
     * Validates the IV stored in the JWT encryption bundle against the expected length.
     *
     * @param EncryptedJwtBundle                            $bundle the bundle containing the IV to validate
     * @param array<string,string|int|class-string<object>> $config
     *                                                              Configuration array (expects 'length' in bits)
     *
     * @throws InvalidInitializationVectorException if the IV is missing or has incorrect length
     */
    public function validateIv(EncryptedJwtBundle $bundle, array $config): void;
}
