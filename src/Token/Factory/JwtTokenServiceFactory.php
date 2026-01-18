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

final class JwtTokenServiceFactory
{
    public static function createDefault(): JwtTokenService
    {
        return self::create();
    }

    public static function create(
        ?JwtTokenCreator $creator = null,
        ?JwtTokenReader $reader = null,
        ?JwtClaimsValidationService $claimsValidator = null,
        ?JwtTokenReissuer $reissuer = null,
    ): JwtTokenService {
        // Shared defaults (so the default graph is consistent)
        $validator        = new JwtValidator();
        $payloadCodec     = new JwtPayloadCodec();
        $issuerFactory    = new JwtTokenIssuerFactory();
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
