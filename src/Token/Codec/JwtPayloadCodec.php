<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Codec;

use JsonException;
use Phithi92\JsonWebToken\Exceptions\Token\InvalidFormatException;
use Phithi92\JsonWebToken\Token\JwtPayload;

use function array_is_list;
use function is_array;
use function is_float;
use function is_int;
use function is_string;
use function sprintf;

/**
 * Codec responsible for encoding/decoding (hydration) of JWT payloads.
 *
 * - Validates decoded JSON payload structures (RFC 7519 semantics)
 * - Ensures registered claim types match RFC requirements
 * - Hydrates claims into a JwtPayload instance
 */
final class JwtPayloadCodec
{
    /**
     * Decode (hydrate) a payload from a decoded JSON value.
     *
     * If an existing JwtPayload instance is provided, the decoded claims are
     * merged into that payload. Existing claims with the same name will be
     * overwritten.
     *
     * If no payload is provided, a new JwtPayload instance is created.
     *
     * The decoded value must represent a valid JWT payload according to
     * RFC 7519 (JSON object, valid JSON values, and correct registered
     * claim types).
     *
     * @param mixed $claims  Decoded JSON value representing the JWT payload
     *                       (typically an associative array from json_decode).
     * @param JwtPayload|null $payload Optional existing payload to hydrate/merge into.
     *
     * @return JwtPayload The hydrated payload instance.
     *
     * @throws InvalidFormatException If the payload structure or claim types are invalid.
     */
    public function decode(mixed $claims, ?JwtPayload $payload = null): JwtPayload
    {
        $this->assertValidPayloadStructure($claims);

        /** @var array<string, mixed> $claims */
        $payload ??= new JwtPayload();

        foreach ($claims as $key => $value) {
            // Use setClaim() to allow hydration without "already exists" collisions.
            // RFC types were already validated above.
            $payload->setClaim($key, $value);
        }

        return $payload;
    }

    /**
     * Encode a JwtPayload into an associative array suitable for json_encode().
     *
     * The returned array represents the JWT payload exactly as stored in the
     * JwtPayload instance.
     *
     * No defaults or implicit claims are added. In particular, this method does
     * NOT automatically set or modify registered claims such as "iat", "nbf",
     * or "exp".
     *
     * @param JwtPayload $payload The payload to encode.
     *
     * @return array<string, mixed> Associative array representation of the payload.
     */
    public function encode(JwtPayload $payload): array
    {
        return $payload->toArray();
    }

    /**
     * Validate payload structure and registered claim types according to RFC 7519.
     *
     * Rules:
     * - Payload must be a JSON object (assoc array)
     * - Keys must be strings
     * - Values must be valid JSON values
     * - Registered claims must match RFC-defined types
     *
     * @throws InvalidFormatException
     */
    private function assertValidPayloadStructure(mixed $data): void
    {
        if (! is_array($data)) {
            throw new InvalidFormatException('Decoded JWT payload must be an object (assoc array).');
        }

        foreach ($data as $key => $value) {
            if (! is_string($key)) {
                throw new InvalidFormatException('All JWT claim keys must be strings.');
            }

            if (! $this->isValidPayloadValue($value)) {
                throw new InvalidFormatException(
                    sprintf("JWT claim value for key '%s' must be a valid JSON value.", $key)
                );
            }

            // Registered Claim Names (RFC 7519)
            switch ($key) {
                case 'iss':
                case 'sub':
                case 'jti':
                    if (! is_string($value)) {
                        throw new InvalidFormatException(
                            sprintf("JWT registered claim '%s' must be a string.", $key)
                        );
                    }
                    break;

                case 'aud':
                    if (is_string($value)) {
                        break;
                    }
                    if (! (is_array($value) && array_is_list($value))) {
                        throw new InvalidFormatException(
                            "JWT registered claim 'aud' must be a string or an array of strings."
                        );
                    }
                    foreach ($value as $aud) {
                        if (! is_string($aud)) {
                            throw new InvalidFormatException(
                                "JWT registered claim 'aud' must be an array of strings."
                            );
                        }
                    }
                    break;

                case 'exp':
                case 'nbf':
                case 'iat':
                    // NumericDate = JSON number
                    if (! (is_int($value) || is_float($value))) {
                        throw new InvalidFormatException(
                            sprintf("JWT registered claim '%s' must be a NumericDate (number).", $key)
                        );
                    }
                    break;

                default:
                    // Private and public claims: no additional RFC restrictions
                    break;
            }
        }
    }

    /**
     * Validate whether a value can be represented as JSON.
     */
    private function isValidPayloadValue(mixed $v): bool
    {
        try {
            json_encode($v, JSON_THROW_ON_ERROR);
            return true;
        } catch (JsonException) {
            return false;
        }
    }
}
