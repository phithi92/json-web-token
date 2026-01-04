<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Builder;

use LogicException;
use Phithi92\JsonWebToken\Algorithm\JwtKeyManager;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Token\Codec\JwtHeaderJsonCodec;
use Phithi92\JsonWebToken\Token\Codec\JwtPayloadJsonCodec;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use UnexpectedValueException;

use function implode;
use function is_string;

/**
 * JwtTokenBuilder is responsible for creating encrypted JWT tokens.
 *
 * This builder provides multiple creation strategies:
 * - `create()`: Generates a token and validates it using a JwtValidator.
 * - `createFromBundle()`: Accepts a pre-constructed token bundle and applies validation.
 * - `createWithoutValidation()`: Generates a token without any claim validation.
 *
 * It supports default KID (Key ID) generation, header construction based on algorithm config,
 * and invokes handlers for token preparation (e.g., encryption).
 *
 * ⚠ This class is intended for use within a controlled context, such as authentication workflows.
 *   The `createWithoutValidation()` method should never be used in production environments.
 */
final class JwtTokenBuilder extends AbstractJwtTokenProcessor
{
    // Separator used when building a default KID (Key ID) from algorithm components
    private const KID_PART_SEPARATOR = '_';

    /**
     * Indicates that the handler chain should be executed in its normal
     * forward order, enabling the *creation* (signing/encrypting) of JWT tokens.
     */
    private const OPERATION = HandlerOperation::Perform;

    private ?JwtValidator $validator = null;

    public function __construct(
        JwtKeyManager $manager,
    ) {
        parent::__construct(self::OPERATION, $manager);
    }

    /**
     * Creates an encrypted JWT bundle with validation.
     *
     * @param string            $algorithm Algorithm to be used for encryption
     * @param JwtPayload|null   $payload   Optional payload
     * @param JwtValidator|null $validator Optional custom validator
     * @param string|null       $kid       Optional key ID
     */
    public function create(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?JwtValidator $validator = null,
        ?string $kid = null,
    ): JwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        $bundle = $this->buildBundle(
            algorithm: $algorithm,
            config: $config,
            payload: $payload,
            kid: $kid
        );

        $this->resolveValidator($validator)->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Creates a validated token from an existing bundle.
     *
     * @param JwtBundle $bundle    Pre-built bundle
     * @param string|null        $algorithm Algorithm override (optional)
     * @param JwtValidator|null  $validator Optional validator
     */
    public function createFromBundle(
        JwtBundle $bundle,
        ?string $algorithm = null,
        ?JwtValidator $validator = null,
    ): JwtBundle {
        $algorithm ??= $bundle->getHeader()->getAlgorithm() ?? '';

        $this->dispatchHandlers($algorithm, $bundle);

        $this->resolveValidator($validator)->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * DO NOT USE in production: skips all validation logic.
     *
     * This method bypasses claim/context validation and should only be used for testing.
     *
     * @throws LogicException If configuration is invalid
     */
    public function createWithoutValidation(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        return $this->buildBundle(
            algorithm: $algorithm,
            config: $config,
            payload: $payload,
            kid: $kid
        );
    }

    private function buildBundle(
        string $algorithm,
        array $config,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        [$typ, $alg, $enc] = $this->resolveHeaderParamsFromConfig($config);

        $header = $this->buildHeader($typ, $alg, $kid, $enc);

        $bundle = new JwtBundle($header, $payload);
        $encryptionData = new JwtEncryptionData(aad: $this->encodeAad($bundle));

        $bundle->setEncryption($encryptionData);

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }

    private function encodeAad(JwtBundle $bundle): string
    {
        $typ = $bundle->getHeader()->getType();

        return match ($typ) {
            'JWE' => $this->encodeJweAad($bundle),
            'JWS' => $this->encodeJwsAad($bundle),
            default => throw new LogicException("Unsupported token type: $typ"),
        };
    }

    private function encodeJweAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        return Base64UrlEncoder::encode($jsonHeader);
    }

    private function encodeJwsAad(JwtBundle $bundle): string
    {
        $jsonHeader = JwtHeaderJsonCodec::encodeStatic($bundle->getHeader());
        $jsonPayload = JwtPayloadJsonCodec::encodeStatic($bundle->getPayload());
        return Base64UrlEncoder::encode($jsonHeader) . '.' .
                Base64UrlEncoder::encode($jsonPayload);
    }

    private function resolveValidator(?JwtValidator $validator = null): JwtValidator
    {
        return $this->validator ??= $validator ?? new JwtValidator();
    }

    /**
     * Extracts core header parameters from algorithm configuration.
     *
     * @param array<string, mixed> $config
     *
     * @return array{string,string|null,string|null} Token type, algorithm, encryption method
     *
     * @throws LogicException If required keys are missing
     */
    private function resolveHeaderParamsFromConfig(array $config): array
    {
        $tokenType = $config['token_type'] ?? null;
        $alg = $config['alg'] ?? null;
        $enc = $config['enc'] ?? null;

        $this->assertValidHeaderConfig($tokenType, $alg, $enc);

        /** @var string $tokenType */
        /** @var string|null $alg */
        /** @var string|null $enc */

        return [$tokenType, $alg, $enc];
    }

    /**
     * Validates extracted header config for basic type correctness.
     *
     * @throws LogicException On invalid types or missing values
     */
    private function assertValidHeaderConfig(
        mixed $tokenType,
        mixed $alg,
        mixed $enc,
    ): void {
        if (! $this->isValidHeaderConfigShape($tokenType, $alg, $enc)) {
            throw new LogicException('Invalid header configuration');
        }
    }

    private function isValidHeaderConfigShape(mixed $tokenType, mixed $alg, mixed $enc): bool
    {
        return is_string($tokenType)
            && (is_string($alg) || $alg === null)
            && (is_string($enc) || $enc === null);
    }

    /**
     * Creates a JwtHeader based on input and defaults.
     *
     * @throws UnexpectedValueException If token header not valid
     * @throws UnresolvableKeyException If kid not found
     */
    private function buildHeader(
        string $typ,
        ?string $alg,
        ?string $kid,
        ?string $enc,
    ): JwtHeader {
        if ($alg === null) {
            throw new UnexpectedValueException('Incomplete token header configuration');
        }

        $kid ??= $this->deriveDefaultKid($alg, $enc);

        $this->assertKnownKid($kid);

        $header = (new JwtHeader())->setType($typ)->setAlgorithm($alg);

        if ($enc !== null) {
            $header->setEnc($enc);
        }

        return $header->setKid($kid);
    }

    /**
     * Validates whether the given KID refers to a known key or passphrase.
     *
     * @throws UnresolvableKeyException
     */
    private function assertKnownKid(string $kid): void
    {
        if (! $this->canResolveKid($kid)) {
            throw new UnresolvableKeyException($kid);
        }
    }

    /**
     * Checks if the key ID maps to a valid key or passphrase.
     */
    private function canResolveKid(string $kid): bool
    {
        return $this->manager->hasKey($kid) || $this->manager->hasPassphrase($kid);
    }

    /**
     * Builds a default KID string from algorithm and encryption method.
     *
     * Example: "RSA_OAEP_A256GCM"
     */
    private function deriveDefaultKid(
        string $alg,
        ?string $enc = null,
        string $seperator = self::KID_PART_SEPARATOR,
    ): string {
        $parts = [];

        if ($alg !== 'dir') {
            $parts[] = $alg;
        }

        if ($enc !== null && $enc !== '') {
            $parts[] = $enc;
        }

        return implode($seperator, $parts);
    }
}
