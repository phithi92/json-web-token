<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Builder;

use LogicException;
use Phithi92\JsonWebToken\Algorithm\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Handler\HandlerOperation;
use Phithi92\JsonWebToken\Token\EncryptedJwtBundle;
use Phithi92\JsonWebToken\Token\JwtHeader;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use UnexpectedValueException;

use function implode;
use function is_string;
use function strtolower;

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

    public function __construct(
        JwtAlgorithmManager $manager,
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
    ): EncryptedJwtBundle {
        $validator ??= new JwtValidator();
        $bundle = $this->createWithoutValidation($algorithm, $payload, $kid);

        $validator->assertValidBundle($bundle);

        return $bundle;
    }

    /**
     * Creates a validated token from an existing bundle.
     *
     * @param EncryptedJwtBundle $bundle    Pre-built bundle
     * @param string|null        $algorithm Algorithm override (optional)
     * @param JwtValidator|null  $validator Optional validator
     */
    public function createFromBundle(
        EncryptedJwtBundle $bundle,
        ?string $algorithm = null,
        ?JwtValidator $validator = null,
    ): EncryptedJwtBundle {
        $algorithm ??= $bundle->getHeader()->getAlgorithm() ?? '';

        $this->dispatchHandlers($algorithm, $bundle);

        $validator ??= new JwtValidator();
        $validator->assertValidBundle($bundle);

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
    ): EncryptedJwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        [$typ, $alg, $enc] = $this->extractHeaderParams($config);

        $header = $this->createHeader($typ, $alg, $kid, $enc);
        $bundle = new EncryptedJwtBundle($header, $payload);

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
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
    private function extractHeaderParams(array $config): array
    {
        $tokenType = $config['token_type'] ?? null;
        $alg = $config['alg'] ?? null;
        $enc = $config['enc'] ?? null;

        $this->assertResolvableHeaderConfig($tokenType, $alg, $enc);

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
    private function assertResolvableHeaderConfig(
        mixed $tokenType,
        mixed $alg,
        mixed $enc,
    ): void {
        if (! $this->isValidHeaderConfig($tokenType, $alg, $enc)) {
            throw new LogicException('Invalid header configuration');
        }
    }

    private function isValidHeaderConfig(mixed $tokenType, mixed $alg, mixed $enc): bool
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
    private function createHeader(
        string $typ,
        ?string $alg,
        ?string $kid,
        ?string $enc,
    ): JwtHeader {
        if ($alg === null) {
            throw new UnexpectedValueException('Incomplete token header configuration');
        }

        $kid ??= $this->buildDefaultKid($alg, $enc);

        $this->assertResolvableKid($kid);

        return $this->buildHeader($typ, $alg, $enc, $kid);
    }

    /**
     * Validates whether the given KID refers to a known key or passphrase.
     *
     * @throws UnresolvableKeyException
     */
    private function assertResolvableKid(string $kid): void
    {
        if (! $this->isResolvableKid($kid)) {
            throw new UnresolvableKeyException($kid);
        }
    }

    /**
     * Checks if the key ID maps to a valid key or passphrase.
     */
    private function isResolvableKid(string $kid): bool
    {
        return $this->manager->hasKey($kid) || $this->manager->hasPassphrase($kid);
    }

    /**
     * Assembles the JwtHeader object from parameters.
     */
    private function buildHeader(
        string $typ,
        string $alg,
        ?string $enc,
        string $kid,
    ): JwtHeader {
        $header = (new JwtHeader())->setType($typ)->setAlgorithm($alg);

        if ($enc !== null) {
            $header->setEnc($enc);
        }

        return $header->setKid($kid);
    }

    /**
     * Builds a default KID string from algorithm and encryption method.
     *
     * Example: "RSA_OAEP_A256GCM"
     */
    private function buildDefaultKid(
        string $alg,
        ?string $enc = null,
        string $seperator = self::KID_PART_SEPARATOR,
    ): string {
        $parts = [];

        if (strtolower($alg) !== 'dir') {
            $parts[] = $alg;
        }

        if ($enc !== null && $enc !== '') {
            $parts[] = $enc;
        }

        return implode($seperator, $parts);
    }
}
