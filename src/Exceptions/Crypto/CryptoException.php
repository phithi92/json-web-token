<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Exceptions\Crypto;

use Exception;
use Phithi92\JsonWebToken\Utilities\EnumUtils;

/**
 * Exception for errors related to algorithm handling.
 *
 * Serves as a base exception for all algorithm-related issues within the application.
 */
abstract class CryptoException extends Exception
{
    public function __construct(string $type, mixed ...$details)
    {
        $case = EnumUtils::fromName(CryptoErrorMessagesEnum::class, $type);
        parent::__construct($case->getMessage(...$details));
    }
}
