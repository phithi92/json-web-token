<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Signature;

interface SignatureHandlerInterface
{
    /**
     * Validates an signature against the given input data.
     *
     * @param non-empty-string $kid Key identifier for the HMAC key
     * @param non-empty-string $algorithm HMAC algorithm (e.g., 'HS256', 'HS384', 'HS512')
     * @param non-empty-string $aad Additional authenticated data to verify
     * @param non-empty-string $signature The signature to validate against
     *
     * @return void
     *
     * @throws SignatureComputationException When signature computation fails
     * @throws InvalidTokenException When signature validation fails
     */
    public function validateSignature(string $kid, string $algorithm, string $aad, string $signature): void;

    /**
     * Compute an signature for given algorithm.
     *
     * @param non-empty-string $kid Key identifier for the private key
     * @param non-empty-string $algorithm Signature algorithm (e.g., 'ES256', 'ES384', 'ES512')
     * @param non-empty-string $signingInput The data to be signed (JWS signing input)
     *
     * @return SignatureHandlerResult
     *
     * @throws SignatureComputationException When signature computation fails
     * @throws InvalidTokenException When signature validation fails
     */
    public function computeSignature(string $kid, string $algorithm, string $signingInput): SignatureHandlerResult;
}
