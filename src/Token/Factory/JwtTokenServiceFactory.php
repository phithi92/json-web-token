<?php

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
        $validator = new JwtValidator();

        $payloadCodec     = new JwtPayloadCodec();
        $issuerFactory    = new JwtTokenIssuerFactory();
        $decryptorFactory = new JwtTokenDecryptorFactory();

        $creator = new JwtTokenCreator(
            issuerFactory: $issuerFactory,
            payloadCodec: $payloadCodec,
            defaultValidator: $validator
        );

        $reader = new JwtTokenReader(
            decryptorFactory: $decryptorFactory
        );

        $claimsValidator = new JwtClaimsValidationService(
            reader: $reader,
            defaultValidator: $validator
        );

        $reissuer = new JwtTokenReissuer(
            creator: $creator,
            payloadCodec: $payloadCodec,
            defaultValidator: $validator,
            issuerFactory: $issuerFactory
        );

        return new JwtTokenService(
            creator: $creator,
            reader: $reader,
            claimsValidator: $claimsValidator,
            reissuer: $reissuer
        );
    }
}
