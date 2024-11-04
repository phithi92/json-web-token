<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * Class Token
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
 * The `build` method facilitates token generation by delegating the construction
 * process to appropriate services depending on the type of the token (JWS or JWE).
 * The class also includes basic validation functionality to ensure the token's
 * components are correctly initialized before generating the final token string.
 *
 * @package TokenManagement
 */
class JwtTokenContainer
{
    private string $type = '';
    private JwtPayload $payload;
    private ?string $encryptedPayload = null; // Verschlüsselter Payload
    private JwtHeader $header;
    private ?string $signature = null;
    private ?string $cek = null; // Verschlüsselter Content Encryption Key
    private ?string $iv = null;  // Initialisierungsvektor
    private ?string $authTag = null;
    private string $encryptedKey = ''; // Verschlüsselter Schlüssel
    private bool $isEncrypted = false; // Flag, um anzuzeigen, ob Payload verschlüsselt ist

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

    public function isEncryptedToken(): bool
    {
        return $this->type === 'JWE';
    }

    // Verschlüsselter Payload setzen
    public function setEncryptedPayload(string $encryptedPayload): self
    {
        $this->encryptedPayload = $encryptedPayload;
        $this->isEncrypted = true;
        return $this;
    }

    // Verschlüsselten Payload abrufen
    public function getEncryptedPayload(): string
    {
        return $this->encryptedPayload;
    }

    // Header setzen
    public function setHeader(JwtHeader $header): self
    {
        $this->header = $header;
        $this->type = $this->header->getType();
        return $this;
    }

    // Header abrufen
    public function getHeader(): JwtHeader
    {
        return $this->header;
    }

    // Signatur setzen
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }

    // Initialisierungsvektor setzen
    public function setIv(string $iv): self
    {
        $this->iv = $iv;
        return $this;
    }

    // Payload setzen
    public function setPayload(JwtPayload $payload): self
    {
        $this->payload = $payload;
        return $this;
    }

    // Payload abrufen
    public function getPayload(): JwtPayload
    {
        return $this->payload;
    }

    // Verschlüsselten Content Encryption Key setzen
    public function setCek(string $cek): self
    {
        $this->cek = $cek;
        return $this;
    }

    // Verschlüsselten Content Encryption Key abrufen
    public function getCek(): string
    {
        return $this->cek;
    }

    // Verschlüsselten Schlüssel setzen
    public function setEncryptedKey(string $encryptedKey): self
    {
        $this->encryptedKey = $encryptedKey;
        $this->isEncrypted = true;
        return $this;
    }

    // Verschlüsselten Schlüssel abrufen
    public function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }

    // Signatur abrufen
    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function setAuthTag(string $tag): self
    {
        $this->authTag = $tag;

        return $this;
    }

    public function getAuthTag(): ?string
    {
        return $this->authTag;
    }

    // Initialisierungsvektor abrufen
    public function getIv(): ?string
    {
        return $this->iv;
    }

    // Flag, um den Verschlüsselungsstatus abzurufen
    public function isEncrypted(): bool
    {
        return $this->isEncrypted;
    }

    // Wandelt das Token in ein Array um
    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'payload' => $this->isEncrypted ? $this->encryptedPayload : $this->payload->toArray(),
            'header' => $this->getHeader()->toArray(),
            'signature' => $this->signature,
            'cek' => $this->cek,
            'iv' => $this->iv,
            'encrypted_key' => $this->encryptedKey,
            'isEncrypted' => $this->isEncrypted,
        ];
    }

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
