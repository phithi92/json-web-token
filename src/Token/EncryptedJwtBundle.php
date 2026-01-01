<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;

/**
 * EncryptedJwtBundle.
 *
 * Internal representation of a JSON-based token during its lifecycle,
 * supporting both JWS and JWE formats. Used for building, decoding,
 * encrypting, decrypting, signing, and verifying tokens.
 */
final class EncryptedJwtBundle
{
    private JwtHeader $header;

    private JwtPayload $payload;

    private JwtEncryptionData $encryption;

    private ?JwtSignature $signature = null;

    /**
     * Initializes the JWT header with an optional JwtPayload instance.
     *
     * If a JwtPayload is provided, it sets this payload during instantiation.
     */
    public function __construct(JwtHeader $header, ?JwtPayload $payload = null)
    {
        $this->header = $header;
        $this->payload = $payload ?? new JwtPayload();
        $this->encryption = new JwtEncryptionData();
    }

    /**
     * Retrieves the JWT header.
     *
     * @return JwtHeader the JWT header
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
     * @param JwtSignature $signature the signature of the JWT
     */
    public function setSignature(JwtSignature $signature): self
    {
        $this->signature = $signature;

        return $this;
    }

    /**
     * Retrieves the payload.
     *
     * @return JwtPayload the JWT payload
     */
    public function getPayload(): JwtPayload
    {
        return $this->payload;
    }

    /**
     * Retrieves the JWT signature.
     *
     * @return string the signature
     */
    public function getSignature(): string
    {
        return $this->signature !== null
            ? (string) $this->signature
            : throw new MissingTokenPart('Signature');
    }
}
