<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Service;

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

final class JwtClaimsValidationService
{
    public function __construct(
        private readonly JwtTokenReader $reader,
        private readonly JwtValidator $defaultValidator,
    ) {
    }
    
    /**
     * Validates the claims of a JWT token using the configured validator.
     *
     * This method decrypts the JWT token without performing claim validation,
     * then validates the claims separately using the provided validator or the
     * service's default validator. Signature and decryption are handled by
     * the JwtTokenReader; this method only concerns itself with claim validation.
     *
     * Validation includes:
     * - Standard claims (iss, sub, aud, exp, nbf, iat, jti)
     * - Custom claims defined in the validator
     * - Claim types and formats
     * - Time-based constraints (exp, nbf, iat)
     *
     * @param string $token The raw JWT token to validate
     * @param JwtKeyManager $manager Key manager used to decrypt the token
     * @param JwtValidator|null $validator Optional validator with custom rules; defaults to the service's default validator
     *
     * @return bool True if all claims are valid, false otherwise
     */   
    public function validateTokenClaims(
        string $token,
        JwtKeyManager $manager,
        ?JwtValidator $validator = null,
    ): bool {
        $validator ??= $this->defaultValidator;

        // Important: we validate claims only; signature/decryption still should happen.
        // So we decrypt WITHOUT claim validation and then run isValid().
        $bundle = $this->reader->decryptTokenWithoutClaimValidation(token: $token, manager: $manager);

        return $validator->isValid(payload: $bundle->getPayload());
    }
}
