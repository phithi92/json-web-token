<?php

namespace Phithi92\JsonWebToken\Interfaces;

use OpenSSLAsymmetricKey;

/**
 * Manages JWT cryptographic operations for symmetric and asymmetric algorithms.
 *
 * This class facilitates the initialization and management of JWT algorithms,
 * supporting both symmetric (e.g., HS256) and asymmetric (e.g., RS256) cryptographic
 * operations. It provides methods to set and retrieve the necessary keys and passphrase.
 *
 * Asymmetric keys (public and private) are validated upon setting, and an
 * exception will be thrown if the keys are invalid. This validation ensures the
 * integrity and security of cryptographic operations, and prevents the use of
 * unsupported or malformed keys.
 */
interface JwtAlgorithmManagerInterface
{
    public function __construct(
        string $algorithm,
        string|null $passphrase = null,
        string|null $public = null,
        string|null $private = null
    );

    /**
     * Gets the passphrase for symmetric algorithms.
     *
     * @return string|null The passphrase, if available.
     */
    public function getPassphrase(): string|null;

    /**
     * Gets the public key for asymmetric algorithms.
     *
     * @return OpenSSLAsymmetricKey|null The public key, if available.
     */
    public function getPublicKey(): OpenSSLAsymmetricKey|null;

    /**
     * Gets the private key for asymmetric algorithms.
     *
     * @return OpenSSLAsymmetricKey|null The private key, if available.
     */
    public function getPrivateKey(): OpenSSLAsymmetricKey|null;
}
