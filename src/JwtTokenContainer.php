<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Utilities\JsonEncoder;
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
    private ?string $type = null; // Type of the token (e.g., JWT, JWE)
    private JwtPayload $payload; // Payload of the JWT
    private ?string $encryptedPayload = null; // Encrypted payload, if applicable
    private JwtHeader $header; // Header of the JWT
    private ?string $signature = null; // Signature of the JWT
    private ?string $cek = null; // Encrypted Content Encryption Key
    private ?string $iv = null;  // Initialization Vector for encryption
    private ?string $authTag = null; // Authentication tag for encryption
    private string $encryptedKey = ''; // Encrypted key associated with the token
    private bool $isEncrypted = false; // Flag to indicate if the payload is encrypted

    /**
     * Constructor to initialize payload and encryption status.
     *
     * @param JwtPayload|null $payload     The payload of the JWT.
     * @param bool            $isEncrypted Indicates whether the payload is encrypted.
     */
    public function __construct(?JwtPayload $payload = null, bool $isEncrypted = false)
    {
        if ($payload !== null) {
            if ($isEncrypted) {
                $this->setEncryptedPayload($payload);
            } else {
                $this->setPayload($payload);
            }
        }
        $this->isEncrypted = $isEncrypted;
    }

    /**
     * Checks if the token is of type JWE (encrypted).
     *
     * @return bool True if the token is encrypted, false otherwise.
     */
    public function isEncryptedToken(): bool
    {
        return $this->type === 'JWE';
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
        $this->isEncrypted = true;
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
        $this->type = $this->header->getType();
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
     * Retrieves the JWT type.
     *
     * @return string The JWT type.
     */
    public function getType(): ?string
    {
        return $this->type;
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
        $this->isEncrypted = true;
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

    /**
     * Checks if the token payload is encrypted.
     *
     * @return bool True if the payload is encrypted, false otherwise.
     */
    public function isEncrypted(): bool
    {
        return $this->isEncrypted;
    }

    /**
     * Converts the token to an associative array.
     *
     * @return array The token represented as an associative array.
     */
    public function toArray(): array
    {
        return [
            'type' => $this->getType(),
            'payload' => $this->isEncrypted() ? $this->getEncryptedPayload() : $this->getPayload()->toArray(),
            'header' => $this->getHeader()->toArray(),
            'signature' => $this->getSignature(),
            'cek' => $this->getCek(),
            'iv' => $this->getIv(),
            'encrypted_key' => $this->getEncryptedKey(),
            'isEncrypted' => $this->isEncrypted(),
        ];
    }

    /**
     * Converts the token to a JSON string.
     *
     * @return string The token represented as a JSON string.
     */
    public function __toString(): string
    {
        return JsonEncoder::encode(
            [
            'header' => $this->getHeader()->toJson(),
            'payload' => $this->getPayload()->toJson(),
            ]
        );
    }
}
