<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Issuer;

use Phithi92\JsonWebToken\Crypto\Pipeline\CryptoOperationDirection;
use Phithi92\JsonWebToken\Exceptions\Config\InvalidAlgorithmConfigurationException;
use Phithi92\JsonWebToken\Exceptions\Config\MissingAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Exceptions\Token\UnsupportedTokenTypeException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Factory\JwtHeaderFactory;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\JwtEncryptionData;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Phithi92\JsonWebToken\Token\JwtTokenKind;
use Phithi92\JsonWebToken\Token\Processor\AbstractJwtTokenProcessor;
use Phithi92\JsonWebToken\Token\Serializer\JwtAadInput;

use function is_string;

/**
 * JwtTokenIssuer builds JWT bundles and runs the handler chain to produce the final token data.
 *
 * DI Option (clean separation):
 * - This class DOES NOT validate claims/bundles.
 * - Validation is done outside (e.g. in JwtTokenCreator / JwtTokenService).
 */
final class JwtTokenIssuer extends AbstractJwtTokenProcessor
{
    private const OPERATION = CryptoOperationDirection::Perform;

    private readonly JwtHeaderFactory $headerFactory;

    public function __construct(JwtKeyManager $manager)
    {
        parent::__construct(self::OPERATION, $manager);
        $this->headerFactory = new JwtHeaderFactory();
    }

    /**
     * Builds a new JWT bundle and runs handler chain (sign/encrypt).
     *
     * NOTE: No validation is performed here.
     *
     * @throws InvalidAlgorithmConfigurationException
     * @throws UnresolvableKeyException
     * @throws UnsupportedTokenTypeException
     */
    public function issue(
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
     * Processes an existing bundle (runs handlers) and returns it.
     *
     * If no algorithm is provided, the algorithm is taken from the bundle header.
     *
     * NOTE: No validation is performed here.
     *
     * @throws MissingAlgorithmException
     */
    public function issueFromBundle(
        JwtBundle $bundle,
        ?string $algorithm = null,
    ): JwtBundle {
        $algorithm ??= $bundle->getHeader()->getAlgorithm()
            ?? throw new MissingAlgorithmException('header.alg');

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }

    /**
     * Builds a JwtBundle for the given algorithm and optional payload.
     *
     * Resolves config, builds header, computes AAD, attaches encryption data,
     * dispatches handlers.
     *
     * @throws InvalidAlgorithmConfigurationException
     * @throws UnresolvableKeyException
     * @throws UnsupportedTokenTypeException
     */
    private function buildBundle(
        string $algorithm,
        ?JwtPayload $payload = null,
        ?string $kid = null,
    ): JwtBundle {
        $config = $this->manager->getConfiguration($algorithm);

        [$typ, $alg, $enc] = $this->resolveHeaderParamsFromConfig($config);

        $header = $this->headerFactory->create($typ, $alg, $kid, $enc);

        $bundle = new JwtBundle($header, $payload);

        $bundle->setEncryption(new JwtEncryptionData(
            aad: JwtAadInput::fromBundle($bundle)->getEncoded()
        ));

        $this->dispatchHandlers($algorithm, $bundle);

        return $bundle;
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array{JwtTokenKind,string|null,string|null}
     *
     * @throws InvalidAlgorithmConfigurationException
     */
    private function resolveHeaderParamsFromConfig(array $config): array
    {
        $tokenType = $config['token_type'] ?? '';
        $alg = $config['alg'] ?? null;
        $enc = $config['enc'] ?? null;

        return [
            JwtTokenKind::fromTypeOrFail($tokenType),
            $this->normalizeOptionalString($alg),
            $this->normalizeOptionalString($enc),
        ];
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
