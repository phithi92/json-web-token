<?php

namespace Phithi92\JsonWebToken\Exception\AlgorithmManager;

use Phithi92\JsonWebToken\Exception\ErrorMessageTrait;

/**
 * Enum for algorithm-related error messages.
 *
 * Uses `getMessage()` to format messages with dynamic details.
 *
 */
enum AlgorithmErrorMessage: string
{
    use ErrorMessageTrait;

    case UNSUPPORTED = 'Algorithm is unsupoorted: %s';
    case EMPTY_FIELD = 'Empty value for %s';
    case INVALID_SECRET_LENGTH = 'Invalid secret length. Got %s byte but expect %s.';
    case INVALID_IV = 'Invalid intitialize vector length. Got %s byte but expect %s.';
    case INVALID_ASYMETRIC_KEY_LENGTH = 'Invalid asymetric key length. Got %s byte but expect %s.';
    case INVALID_ASYMETRIC_KEY = 'Invalid asymetric key: ';
    case VERIFICATION_FAILED = 'Verification failed: %s';
    case DECRYPTION_FAILED = 'Decryption failed: %s';
    case ENCRYPTION_FAILED = 'Encryption failed: %s';
    case SIGN_FAILED = 'Signin failed: %s';
}
