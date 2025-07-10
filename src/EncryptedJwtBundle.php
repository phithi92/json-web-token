<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtHeader;
use Phithi92\JsonWebToken\JwtEncryptionData;
use Phithi92\JsonWebToken\Interfaces\EncryptedJwtInterface;

/**
 * EncryptedJwtBundle
 *
 * The class provides functionality to set and retrieve key components of a token,
 * such as the header, payload, signature, content encryption key (CEK), and initialization vector (IV).
 *
 * - Header: Contains metadata about the token such as the type (e.g., JWS, JWE).
 * - Payload: Contains the data to be signed or encrypted.
 * - Signature: Holds the digital signature for JWS tokens.
 * - CEK: The content encryption key used in encryption for JWE tokens.
 * - IV: The initialization vector for encryption processes.
 */
final class EncryptedJwtBundle implements EncryptedJwtInterface
{
    private JwtHeader $header;
    private JwtPayload $payload;
    private JwtEncryptionData $encryption;
    private ?string $signature = null;

    /**
     * Initializes the JWT header with an optional JwtPayload instance.
     *
     * If a JwtPayload is provided, it sets this payload during instantiation.
     *
     * @param JwtHeader $header
     * @param JwtPayload $payload
     */
    public function __construct(JwtHeader $header, JwtPayload $payload)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->encryption = new JwtEncryptionData();
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
     * @return JwtEncryptionData handle token encryption data
     */
    public function getEncryption(): JwtEncryptionData
    {
        return $this->encryption;
    }

    /**
     * Sets the JWT signature.
     *
     * @param string $signature The signature of the JWT.
     */
    public function setSignature(string $signature): self
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * Retrieves the payload.
     *
     * @return JwtPayload The JWT payload, or null if not set.
     */
    public function getPayload(): JwtPayload
    {
        return $this->payload;
    }

    /**
     * Retrieves the JWT signature.
     *
     * @return string|null The signature, or null if not set.
     */
    public function getSignature(): ?string
    {
        return $this->signature ?? null;
    }
}
