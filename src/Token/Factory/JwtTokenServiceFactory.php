<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Factory;

use Phithi92\JsonWebToken\Token\Codec\JwtPayloadCodec;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Service\JwtClaimsValidationService;
use Phithi92\JsonWebToken\Token\Service\JwtTokenCreator;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

/**
 * Factory for creating fully configured JwtTokenService instances.
 *
 * This factory builds a consistent default dependency graph for all JWT
 * operations such as token creation, reading, validation, and reissuing.
 * Shared core components (validators, codecs, and factories) are reused
 * to ensure consistent behavior across all sub-services.
 *
 * Individual components can be overridden to customize behavior (for example
 * in tests or alternative implementations) while the remaining defaults
 * stay intact.
 */
final class JwtTokenServiceFactory
{
    /**
     * Creates a JwtTokenService using only default implementations.
     *
     * @return JwtTokenService
     */
    public static function createDefault(): JwtTokenService
    {
        return self::create();
    }

    /**
     * Creates a JwtTokenService with optional custom components.
     *
     * Any dependency passed as null will be replaced by the factory's default
     * implementation. Defaults are wired together using shared instances to
     * guarantee a consistent validation and processing pipeline.
     *
     * @param JwtTokenCreator|null            $creator         Custom token creator
     * @param JwtTokenReader|null             $reader          Custom token reader
     * @param JwtClaimsValidationService|null $claimsValidator Custom claims validator
     * @param JwtTokenReissuer|null           $reissuer        Custom token reissuer
     *
     * @return JwtTokenService
     */
    public static function create(
        ?JwtTokenCreator $creator = null,
        ?JwtTokenReader $reader = null,
        ?JwtClaimsValidationService $claimsValidator = null,
        ?JwtTokenReissuer $reissuer = null,
    ): JwtTokenService {
        // Shared defaults (so the default graph is consistent)
        $validator = new JwtValidator();
        $payloadCodec = new JwtPayloadCodec();
        $issuerFactory = new JwtTokenIssuerFactory();
        $decryptorFactory = new JwtTokenDecryptorFactory();

        // Build default graph
        $defaultCreator = new JwtTokenCreator(
            issuerFactory: $issuerFactory,
            payloadCodec: $payloadCodec,
            defaultValidator: $validator
        );

        $defaultReader = new JwtTokenReader(
            decryptorFactory: $decryptorFactory
        );

        $defaultClaimsValidator = new JwtClaimsValidationService(
            reader: $defaultReader,
            defaultValidator: $validator
        );

        $defaultReissuer = new JwtTokenReissuer(
            payloadCodec: $payloadCodec,
            defaultValidator: $validator,
            issuerFactory: $issuerFactory
        );

        return new JwtTokenService(
            creator: $creator ?? $defaultCreator,
            reader: $reader ?? $defaultReader,
            claimsValidator: $claimsValidator ?? $defaultClaimsValidator,
            reissuer: $reissuer ?? $defaultReissuer,
        );
    }
}
