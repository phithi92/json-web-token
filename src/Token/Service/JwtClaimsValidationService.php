<?php

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;

namespace Phithi92\JsonWebToken\Token\Service;

final class JwtClaimsValidationService
{
    public function __construct(
        private readonly JwtTokenReader $reader,
        private readonly JwtValidator $defaultValidator,
    ) {
    }

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
