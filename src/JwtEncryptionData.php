<?php

namespace Phithi92\JsonWebToken;

/**
 * Holds cryptographic data used in JSON Web Encryption (JWE),
 * including the CEK, IV, AAD, auth tag, and encrypted key if applicable.
 *
 * Serves as a value object within the JWE encryption/decryption process.
 */
final class JwtEncryptionData
{
    private string $cek;
    private string $iv;
    private string $authTag;
    private string $encryptedKey;
    private string $aad;

    /**
     * Sets the Base64URL-encoded AAD (Additional Authenticated Data),
     * typically the protected header from the JWE compact serialization.
     *
     * @param string $encodedHeader
     * @return self
     */
    public function setAad(string $encodedHeader): self
    {
        $this->aad = $encodedHeader;
        return $this;
    }

    /**
     * Returns the Base64URL-encoded AAD (Additional Authenticated Data).
     *
     * @return string
     */
    public function getAad(): string
    {
        return $this->aad;
    }

    /**
     *
     * @param string $iv
     * @return self
     */
    public function setIv(string $iv): self
    {
        $this->iv = $iv;
        return $this;
    }

    /**
     * Sets the encrypted Content Encryption Key (CEK).
     *
     * @param  string $cek The content encryption key.
     * @return self
     */
    public function setCek(string $cek): self
    {
        $this->cek = $cek;
        return $this;
    }

    /**
     * Retrieves the encrypted Content Encryption Key.
     *
     * @return string|null The encryption key, or null if not set.
     */
    public function getCek(): ?string
    {
        return $this->cek ?? null;
    }

    /**
     * Sets the encrypted key for the token.
     *
     * @param  string $encryptedKey The encrypted key.
     * @return self
     */
    public function setEncryptedKey(string $encryptedKey): self
    {
        $this->encryptedKey = $encryptedKey;
        return $this;
    }

    /**
     * Retrieves the encrypted key.
     *
     * @return string|null The encrypted key, or null if not set.
     */
    public function getEncryptedKey(): ?string
    {
        return $this->encryptedKey ?? null;
    }

    /**
     * Sets the authentication tag for encryption.
     *
     * @param  string $tag The authentication tag.
     * @return self
     */
    public function setAuthTag(string $tag): self
    {
        $this->authTag = $tag;
        return $this;
    }

    /**
     * Retrieves the authentication tag.
     *
     * @return string|null The authentication tag, or null if not set.
     */
    public function getAuthTag(): ?string
    {
        return $this->authTag ?? null;
    }

    /**
     * Retrieves the Initialization Vector (IV).
     *
     * @return string|null The initialization vector, or null if not set.
     */
    public function getIv(): ?string
    {
        return $this->iv ?? null;
    }
}
