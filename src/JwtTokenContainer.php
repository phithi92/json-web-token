<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;

/**
 * JwtTokenContainer
 *
 * This class is responsible for managing the creation and validation of tokens,
 * which may represent either a JSON Web Signature (JWS) or a JSON Web Encryption (JWE).
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
 * @package json-web-token
 * @author Phillip Thiele <development@phillip-thiele.de>
 * @version 1.0.0
 * @since 1.0.0
 * @license https://github.com/phithi92/json-web-token/blob/main/LICENSE MIT License
 * @link https://github.com/phithi92/json-web-token Project on GitHub
 */
class JwtTokenContainer
{
    private JwtPayload $payload; // Payload of the JWT
    private ?string $encryptedPayload = null; // Encrypted payload, if applicable
    private JwtHeader $header; // Header of the JWT
    private ?string $signature = null; // Signature of the JWT
    private ?string $cek = null; // Encrypted Content Encryption Key
    private ?string $iv = null;  // Initialization Vector for encryption
    private ?string $authTag = null; // Authentication tag for encryption
    private string $encryptedKey = ''; // Encrypted key associated with the token

    /**
     * Constructor to initialize payload and encryption status.
     *
     * @param JwtPayload|null $payload     The payload of the JWT.
     */
    public function __construct(?JwtPayload $payload = null)
    {
        if ($payload !== null) {
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
     * @return string The encrypted payload data.
     */
    public function getEncryptedPayload(): string
    {
        return $this->encryptedPayload;
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
     * @return JwtPayload The JWT payload.
     */
    public function getPayload(): JwtPayload
    {
        return $this->payload;
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
     * @return string The content encryption key.
     */
    public function getCek(): string
    {
        return $this->cek;
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
     * @return string The encrypted key.
     */
    public function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }

    /**
     * Retrieves the JWT signature.
     *
     * @return string|null The signature, or null if not set.
     */
    public function getSignature(): ?string
    {
        return $this->signature;
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
        return $this->authTag;
    }

    /**
     * Retrieves the Initialization Vector (IV).
     *
     * @return string|null The initialization vector, or null if not set.
     */
    public function getIv(): ?string
    {
        return $this->iv;
    }
}
