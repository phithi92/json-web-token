<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

/**
 * Holds cryptographic data used in JSON Web Encryption (JWE),
 * including the CEK, IV, AAD, auth tag, and encrypted key if applicable.
 *
 * Serves as a value object within the JWE encryption/decryption process.
 */
final class JwtEncryptionData
{
    // Content Encryption Key (symmetric key used for data encryption)
    private string $cek;

    // Initialization Vector for encryption (ensures randomness)
    private string $iv;

    // Authentication tag used to verify data integrity and authenticity
    private string $authTag;

    // Encrypted version of the CEK (e.g., encrypted with recipient's public key)
    private string $encryptedKey;

    // Additional Authenticated Data (extra data authenticated but not encrypted)
    private string $aad;

    /**
     * Sets the Base64URL-encoded AAD (Additional Authenticated Data),
     * typically the protected header from the JWE compact serialization.
     *
     * @return self For method chaining.
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
        if (! isset($this->aad)) {
            throw new \LogicException('AAD has not been set.');
        }

        return $this->aad;
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
     * @param string $cek The content encryption key.
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
     * @return string The encryption key.
     */
    public function getCek(): string
    {
        if (! isset($this->cek)) {
            throw new \LogicException('CEK has not been set.');
        }

        return $this->cek;
    }

    /**
     * Sets the encrypted key for the token.
     *
     * @param string $encryptedKey The encrypted key.
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
     * @return string The encrypted key.
     */
    public function getEncryptedKey(): string
    {
        if (! isset($this->encryptedKey)) {
            throw new \LogicException('Encrypted Key has not been set.');
        }

        return $this->encryptedKey;
    }

    /**
     * Sets the authentication tag for encryption.
     *
     * @param string $tag The authentication tag.
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
     * @return string The authentication tag.
     */
    public function getAuthTag(): string
    {
        if (! isset($this->authTag)) {
            throw new \LogicException('AuthTag has not been set.');
        }

        return $this->authTag;
    }

    /**
     * Retrieves the Initialization Vector (IV).
     *
     * @return string The initialization vector.
     */
    public function getIv(): string
    {
        if (! isset($this->iv)) {
            throw new \LogicException('IV has not been set.');
        }

        return $this->iv;
    }
}
