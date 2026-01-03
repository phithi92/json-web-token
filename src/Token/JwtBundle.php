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
    ) {
        $this->header = $header;
        $this->payload = $payload ?? new JwtPayload();
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
        return $this->encryption ??= new JwtEncryptionData();
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
     *
     * @throws MissingTokenPart
     */
    public function getSignature(): JwtSignature
    {
        return $this->signature ?? throw new MissingTokenPart('Signature');
    }

    public function hasSignature(): bool
    {
        return $this->signature !== null;
    }
}
