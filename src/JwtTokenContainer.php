<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;

/**
 * JwtTokenContainer
 *
 * The class provides functionality to set and retrieve key components of a token,
 * such as the header, payload, signature, content encryption key (CEK), and initialization vector (IV).
 *
 * - Header: Contains metadata about the token such as the type (e.g., JWS, JWE).
 * - Payload: Contains the data to be signed or encrypted.
 * - Signature: Holds the digital signature for JWS tokens.
 * - CEK: The content encryption key used in encryption for JWE tokens.
 * - IV: The initialization vector for encryption processes.
 *
 * @package Phithi92\JsonWebToken
 * @author  Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since   1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link    https://github.com/phithi92/json-web-token Project on GitHub
 */
final class JwtTokenContainer
{
    private JwtPayload $payload; // Payload of the JWT
    private string $encryptedPayload; // Encrypted payload, if applicable
    private JwtHeader $header; // Header of the JWT
    private string $signature; // Signature of the JWT
    private string $cek; // Encrypted Content Encryption Key
    private string $iv;  // Initialization Vector for encryption
    private string $authTag; // Authentication tag for encryption
    private string $encryptedKey; // Encrypted key associated with the token

    /**
     * Initializes the JWT header with an optional JwtPayload instance.
     *
     * If a JwtPayload is provided, it sets this payload during instantiation.
     *
     * @param JwtPayload|null $payload Optional JwtPayload instance to initialize the header.
     */
    public function __construct(JwtPayload|null $payload = null)
    {
        if ($payload) {
            $this->setPayload($payload);
        }
    }

    /**
     * Sets the encrypted payload.
     *
     * @param  string $encryptedPayload The encrypted payload data.
     * @return self
     */
    public function setEncryptedPayload(string $encryptedPayload): self
    {
        $this->encryptedPayload = $encryptedPayload;
        return $this;
    }

    /**
     * Retrieves the encrypted payload.
     *
     * @return string|null The encrypted payload data, or null if not set.
     */
    public function getEncryptedPayload(): string|null
    {
        return $this->encryptedPayload ?? null;
    }

    /**
     * Sets the JWT header.
     *
     * @param  JwtHeader $header The JWT header.
     * @return self
     */
    public function setHeader(JwtHeader $header): self
    {
        $this->header = $header;
        return $this;
    }

    /**
     * Retrieves the JWT header.
     *
     * @return JwtHeader The JWT header.
     */
    public function getHeader(): JwtHeader
    {
        return $this->header;
    }

    /**
     * Sets the JWT signature.
     *
     * @param  string $signature The signature of the JWT.
     * @return self
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * Sets the Initialization Vector (IV) for encryption.
     *
     * @param  string $iv The initialization vector.
     * @return self
     */
    public function setIv(string $iv): self
    {
        $this->iv = $iv;
        return $this;
    }

    /**
     * Sets the payload.
     *
     * @param  JwtPayload $payload The JWT payload.
     * @return self
     */
    public function setPayload(JwtPayload $payload): self
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * Retrieves the payload.
     *
     * @return JwtPayload|null The JWT payload, or null if not set.
     */
    public function getPayload(): JwtPayload|null
    {
        return $this->payload ?? null;
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
    public function getCek(): string|null
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
    public function getEncryptedKey(): string|null
    {
        return $this->encryptedKey ?? null;
    }

    /**
     * Retrieves the JWT signature.
     *
     * @return string|null The signature, or null if not set.
     */
    public function getSignature(): string|null
    {
        return $this->signature ?? null;
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
    public function getAuthTag(): string|null
    {
        return $this->authTag ?? null;
    }

    /**
     * Retrieves the Initialization Vector (IV).
     *
     * @return string|null The initialization vector, or null if not set.
     */
    public function getIv(): string|null
    {
        return $this->iv ?? null;
    }
}
