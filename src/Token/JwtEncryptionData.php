<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;

/**
 * Holds cryptographic data used in JSON Web Encryption (JWE),
 * including the CEK, IV, AAD, auth tag, and encrypted key if applicable.
 *
 * Serves as a value object within the JWE encryption/decryption process.
 */
final class JwtEncryptionData
{
    // Content Encryption Key (symmetric key used for data encryption)
    private ?string $cek = null;

    // Initialization Vector for encryption (ensures randomness)
    private ?string $iv = null;

    // Authentication tag used to verify data integrity and authenticity
    private ?string $authTag = null;

    // Encrypted version of the CEK (e.g., encrypted with recipient's public key)
    private ?string $encryptedKey = null;

    // Additional Authenticated Data (extra data authenticated but not encrypted)
    private ?string $aad = null;

    /**
     * Sets the Base64URL-encoded AAD (Additional Authenticated Data),
     * typically the protected header from the JWE compact serialization.
     *
     * @return self for method chaining
     */
    public function setAad(string $encodedHeader): self
    {
        $this->aad = $encodedHeader;

        return $this;
    }

    /**
     * Returns the Base64URL-encoded AAD (Additional Authenticated Data).
     *
     * @return string get aad
     */
    public function getAad(): string
    {
        return $this->aad ?? throw new MissingTokenPart('AAD');
    }

    /**
     * Sets initialization vector.
     *
     * @return self For method chaining
     */
    public function setIv(string $iv): self
    {
        $this->iv = $iv;

        return $this;
    }

    /**
     * Sets the encrypted Content Encryption Key (CEK).
     *
     * @param string $cek the content encryption key
     *
     * @return self For method chaining
     */
    public function setCek(string $cek): self
    {
        $this->cek = $cek;

        return $this;
    }

    /**
     * Retrieves the encrypted Content Encryption Key.
     *
     * @return string the encryption key
     */
    public function getCek(): string
    {
        return $this->cek ?? throw new MissingTokenPart('CEK');
    }

    /**
     * Sets the encrypted key for the token.
     *
     * @param string $encryptedKey the encrypted key
     *
     * @return self For method chaining
     */
    public function setEncryptedKey(string $encryptedKey): self
    {
        $this->encryptedKey = $encryptedKey;

        return $this;
    }

    /**
     * Retrieves the encrypted key.
     *
     * @return string the encrypted key
     */
    public function getEncryptedKey(): string
    {
        return $this->encryptedKey ?? throw new MissingTokenPart('EncryptedKey');
    }

    /**
     * Sets the authentication tag for encryption.
     *
     * @param string $tag the authentication tag
     *
     * @return self For method chaining
     */
    public function setAuthTag(string $tag): self
    {
        $this->authTag = $tag;

        return $this;
    }

    /**
     * Retrieves the authentication tag.
     *
     * @return string the authentication tag
     */
    public function getAuthTag(): string
    {
        return $this->authTag ?? throw new MissingTokenPart('AuthTag');
    }

    /**
     * Retrieves the Initialization Vector (IV).
     *
     * @return string the initialization vector
     */
    public function getIv(): string
    {
        return $this->iv ?? throw new MissingTokenPart('IV');
    }
}
