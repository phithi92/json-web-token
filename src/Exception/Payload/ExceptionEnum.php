<?php

/**
 * This file is part of the phithi92\JsonWebToken package.
 *
 * @package phithi92\JsonWebToken\Exception\Payload
 * @license MIT License
 */

namespace Phithi92\JsonWebToken\Exception\Payload;

/**
 * Class ExceptionEnum
 *
 * Enum class that defines various error messages used in payload validation exceptions.
 *
 * @author Phillip Thiele <development@phillip-thiele.de>
 */
class ExceptionEnum
{
    public const MISSING_PAYLOAD_DATA = 'Payload validation failed. The %s is required in the body but was not found';

    public const INVALID_TOKEN_IAT_TO_EARLY = "Issued at (iat) must be earlier than expiration (exp).";
    public const INVALID_TOKEN_NBF_TO_EARLY = "Not before (nbf) must be earlier than expiration (exp).";
    public const INVALID_TOKEN_NBF_EARLY_IAT = "Not before (nbf) must be later than or equal to issued at (iat).";

    public const INVALID_TOKEN_EXPIRED = "Payload is expired";
    public const INVALID_TOKEN_MALFORMT = 'Payload is malformed';

    public const TOKEN_NOT_YET_VALID = 'Payload is not valid yet';
    public const TOKEN_IAT_IN_FUTURE = 'The token "issued at" (iat) date is in the future.';

    public const INVALID_AUDIENCE = 'Invalid audience. Expect %s got %s';
    public const INVALID_ISSUER = 'Invalid Issuer. Expect %s got %s';

    public const ERROR_DATE_FORMAT = "Invalid date %s";

    public const KEY_ALREADY_EXIST = 'Cannot overwrite existing data';
}
