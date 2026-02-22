<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token;

use Phithi92\JsonWebToken\Exceptions\Token\MissingTokenPart;
use Phithi92\JsonWebToken\Exceptions\Token\SignatureAlreadySetException;

/**
 * JwtBundle.
 *
 * Internal representation of a JSON-based token during its lifecycle,
 * supporting both JWS and JWE formats. Used for building, decoding,
 * encrypting, decrypting, signing, and verifying tokens.
 */
final class JwtBundle
{
    private readonly JwtHeader $header;

    private readonly JwtPayload $payload;

    private ?JwtEncryptionData $encryption = null;

    private ?JwtSignature $signature = null;

    /**
     * Initializes the JWT header with an optional JwtPayload instance.
     *
     * If a JwtPayload is provided, it sets this payload during instantiation.
     */
    public function __construct(
        JwtHeader $header,
        ?JwtPayload $payload = null,
        ?JwtEncryptionData $encryption = null,
        ?JwtSignature $signature = null
    ) {
        $this->header = $header;
        $this->payload = $payload ?? new JwtPayload();
        $this->encryption = $encryption;
        $this->signature = $signature;
    }

    /**
     * Retrieves the JWT header.
     */
    public function getHeader(): JwtHeader
    {
        return $this->header;
    }

    /**
     * Retrieves the JWT payload.
     */
    public function getPayload(): JwtPayload
    {
        return $this->payload;
    }

    /**
     * Returns the JWT encryption data.
     *
     * If no encryption data is set, a new instance is created and returned.
     */
    public function getEncryption(): JwtEncryptionData
    {
        return $this->encryption ?? throw new MissingTokenPart('Encryption');
    }

    public function hasEncryption(): bool
    {
        return $this->encryption !== null;
    }

    public function setEncryption(JwtEncryptionData $encryption): self
    {
        $this->encryption = $encryption;
        return $this;
    }

    /**
     * Retrieves the JWT signature.
     *
     * @throws MissingTokenPart If the signature is not present
     */
    public function getSignature(): JwtSignature
    {
        return $this->signature ?? throw new MissingTokenPart('Signature');
    }

    /**
     * Determines whether a JWT signature is present.
     *
     * @return bool True if the signature is set, false if it is null
     */
    public function hasSignature(): bool
    {
        return $this->signature !== null;
    }

    /**
     * Sets the JWT signature.
     *
     * @param JwtSignature $signature the signature of the JWT
     *
     * @throws SignatureAlreadySetException
     */
    public function setSignature(JwtSignature $signature): self
    {
        if ($this->signature !== null) {
            throw new SignatureAlreadySetException();
        }

        $this->signature = $signature;
        return $this;
    }
}
