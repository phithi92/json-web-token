<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;

/**
 * Holds cryptographic data used in JSON Web Encryption (JWE),
 * including the CEK, IV, AAD, auth tag, and encrypted key if applicable.
 *
 * Immutable value object within the JWE encryption/decryption process.
 */
final class JwtEncryptionData
{
    private ?string $cek;
    private ?string $iv;
    private ?string $authTag;
    private ?string $encryptedKey;
    private ?string $aad;

    public function __construct(
        ?string $cek = null,
        ?string $iv = null,
        ?string $authTag = null,
        ?string $encryptedKey = null,
        ?string $aad = null,
    ) {
        $this->cek = $cek;
        $this->iv = $iv;
        $this->authTag = $authTag;
        $this->encryptedKey = $encryptedKey;
        $this->aad = $aad;
    }

    /**
     * Returns a copy with Base64URL-encoded AAD set.
     */
    public function withAad(string $aad): self
    {
        $clone = clone $this;
        $clone->aad = $aad;

        return $clone;
    }

    /**
     * Returns the Base64URL-encoded AAD (Additional Authenticated Data).
     */
    public function getAad(): string
    {
        return $this->aad ?? throw new MissingTokenPart('aad');
    }

    /**
     * Returns a copy with initialization vector set.
     */
    public function withIv(string $iv): self
    {
        $clone = clone $this;
        $clone->iv = $iv;

        return $clone;
    }

    /**
     * Retrieves the Initialization Vector (IV).
     */
    public function getIv(): string
    {
        return $this->iv ?? throw new MissingTokenPart('iv');
    }

    /**
     * Returns a copy with the Content Encryption Key (CEK) set.
     */
    public function withCek(string $cek): self
    {
        $clone = clone $this;
        $clone->cek = $cek;

        return $clone;
    }

    /**
     * Retrieves the Content Encryption Key.
     */
    public function getCek(): string
    {
        return $this->cek ?? throw new MissingTokenPart('cek');
    }

    /**
     * Returns a copy with the encrypted key set.
     */
    public function withEncryptedKey(string $encryptedKey): self
    {
        $clone = clone $this;
        $clone->encryptedKey = $encryptedKey;

        return $clone;
    }

    /**
     * Retrieves the encrypted key.
     */
    public function getEncryptedKey(): string
    {
        return $this->encryptedKey ?? throw new MissingTokenPart('encrypted_key');
    }

    /**
     * Returns a copy with the authentication tag set.
     */
    public function withAuthTag(string $tag): self
    {
        $clone = clone $this;
        $clone->authTag = $tag;

        return $clone;
    }

    /**
     * Retrieves the authentication tag.
     */
    public function getAuthTag(): string
    {
        return $this->authTag ?? throw new MissingTokenPart('tag');
    }

    public function hasAad(): bool
    {
        return $this->aad !== null;
    }

    public function hasIv(): bool
    {
        return $this->iv !== null;
    }

    public function hasCek(): bool
    {
        return $this->cek !== null;
    }

    public function hasEncryptedKey(): bool
    {
        return $this->encryptedKey !== null;
    }

    public function hasAuthTag(): bool
    {
        return $this->authTag !== null;
    }
}
