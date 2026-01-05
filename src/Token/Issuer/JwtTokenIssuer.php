<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Issuer;

use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Exceptions\Config\MissingAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Token\UnsupportedTokenTypeException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Exceptions\Token\MissingHeaderAlgorithmException;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;

use function is_string;

/**
 * JwtTokenBuilder builds JWT bundles and runs the handler chain to produce the final token data.
 *
 * Public API:
 * - create(): builds a new bundle and validates it
 * - createFromBundle(): processes an existing bundle and validates it
 * - createWithoutValidation(): builds a new bundle without validation (testing only)
 *
 * The builder:
 * - resolves header parameters from algorithm configuration
 * - derives a default KID when none is provided
 * - computes AAD for JWE/JWS and attaches it to the bundle
 * - dispatches handlers for signing/encryption
 *
 * ⚠ createWithoutValidation() should only be used in tests or controlled environments.
 */
final class JwtTokenIssuer extends AbstractJwtTokenProcessor
{
    /**
     * Handler chain operation for building tokens (signing/encrypting).
     */
    private const OPERATION = HandlerOperation::Perform;

    private ?JwtValidator $validator = null;
    
    public function __construct(
        JwtKeyManager $manager
    ) {
        parent::__construct(self::OPERATION, $manager);
    }

    /**
     * Builds a new JWT bundle and validates it.
     *
     * @param string            $algorithm Algorithm identifier.
     * @param JwtPayload|null   $payload   Optional payload.
     * @param JwtValidator|null $validator Optional validator override.
     * @param string|null       $kid       Optional key ID; derived if omitted.
     *
     * @throws InvalidAlgorithmConfigurationException If the algorithm configuration is invalid.
     * @throws MissingHeaderAlgorithmException        If the header algorithm (alg) is missing.
     * @throws UnresolvableKeyException               If the resolved or derived KID cannot be found.
     */
    public function create(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $bundle = $this->buildBundle(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );

        $this->resolveValidator($validator)->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Processes an existing bundle (runs handlers) and validates it.
     *
     * If no algorithm is provided, the algorithm is taken from the bundle header.
     *
     * @param JwtBundle         $bundle     Pre-built bundle.
     * @param string|null       $algorithm  Algorithm override (optional).
     * @param JwtValidator|null $validator  Optional validator override.
     *
     * @throws MissingAlgorithmException If no algorithm is available for processing.
     */
    public function createFromBundle(
        JwtBundle $bundle,
        ?string $algorithm = null,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $algorithm ??= $bundle->getHeader()->getAlgorithm()
            ?? throw new MissingAlgorithmException('header.alg');

        $this->dispatchHandlers($algorithm, $bundle);

        $this->resolveValidator($validator)->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Builds a new JWT bundle without running any validation.
     *
     * ⚠ Intended for testing only.
     *
     * @param string          $algorithm Algorithm identifier.
     * @param JwtPayload|null $payload   Optional payload.
     * @param string|null     $kid       Optional key ID; derived if omitted.
     *
     * @throws InvalidAlgorithmConfigurationException If the algorithm configuration is invalid.
     * @throws MissingHeaderAlgorithmException        If the header algorithm (alg) is missing.
     * @throws UnresolvableKeyException               If the resolved or derived KID cannot be found.
     */
    public function createWithoutValidation(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        return $this->buildBundle(
            algorithm: $algorithm,
            payload: $payload,
            kid: $kid
        );
    }

    /**
     * Builds a JwtBundle for the given algorithm and optional payload.
     *
     * Resolves the algorithm configuration, builds the JWT header,
     * computes AAD, and executes the handler chain.
     *
     * @param string          $algorithm Algorithm identifier.
     * @param JwtPayload|null $payload   Optional payload.
     * @param string|null     $kid       Optional key ID; derived if omitted.
     *
     * @throws InvalidAlgorithmConfigurationException If the algorithm configuration is invalid.
     * @throws MissingHeaderAlgorithmException        If the header algorithm (alg) is missing.
     * @throws UnresolvableKeyException               If the resolved or derived KID cannot be found.
     * @throws UnsupportedTokenTypeException          If the token type is not supported.
     */
    private function buildBundle(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        [$typ, $alg, $enc] = $this->resolveHeaderParamsFromConfig($config);

        $header = $this->headerFactory()->create($typ, $alg, $kid, $enc);

        $bundle = new JwtBundle($header, $payload);
        $encryptionData = new JwtEncryptionData(aad: $this->encodeAad($bundle));

        $bundle->setEncryption($encryptionData);

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }

    /**
     * Encodes Additional Authenticated Data (AAD) depending on token type.
     *
     * @throws UnsupportedTokenTypeException If the token type is not supported.
     */
    private function encodeAad(JwtBundle $bundle): string
    {
        $type = $bundle->getHeader()->getType();
        if ($type === null) {
            throw new UnsupportedTokenTypeException('null');
        }

        return match ($type) {
            'JWE' => $this->encodeJweAad($bundle),
            'JWS' => $this->encodeJwsAad($bundle),
            default => throw new UnsupportedTokenTypeException($type),
        };
    }

    /**
     * Encodes AAD for JWE as Base64Url(header-json).
     */
    private function encodeJweAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());

        return Base64UrlEncoder::encode($jsonHeader);
    }

    /**
     * Encodes AAD for JWS as Base64Url(header-json) + '.' + Base64Url(payload-json).
     */
    private function encodeJwsAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        $jsonPayload = JwtPayloadJsonCodec::encodeStatic($bundle->getPayload());

        return Base64UrlEncoder::encode($jsonHeader) . '.'
            . Base64UrlEncoder::encode($jsonPayload);
    }

    /**
     * Resolves the validator instance (uses the provided validator or a cached default).
     */
    private function resolveValidator(?JwtValidator $validator = null): JwtValidator
    {
        return $this->validator ??= $validator ?? new JwtValidator();
    }

    /**
     * Resolves required header parameters from algorithm configuration.
     *
     * @param array<string, mixed> $config
     *
     * @return array{string,string|null,string|null} token type, algorithm, encryption method
     *
     * @throws InvalidAlgorithmConfigurationException If the configuration shape is invalid.
     */
    private function resolveHeaderParamsFromConfig(array $config): array
    {
        $tokenType = $config['token_type'] ?? null;
        $alg = $config['alg'] ?? null;
        $enc = $config['enc'] ?? null;

        return [
            $this->normalizeTokenType($tokenType),
            $this->normalizeOptionalString($alg),
            $this->normalizeOptionalString($enc),
        ];
    }
    
    private function normalizeTokenType(mixed $tokenType): string
    {
        if (! is_string($tokenType)) {
            throw new InvalidAlgorithmConfigurationException();
        }

        return $tokenType;
    }

    private function normalizeOptionalString(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new InvalidAlgorithmConfigurationException();
        }

        return $value;
    }    
}
