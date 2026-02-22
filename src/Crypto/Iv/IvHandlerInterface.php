<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Crypto\Iv;

interface IvHandlerInterface
{
    /**
     * Prepares or generates the Initialization Vector (IV)
     * and attaches it to the given JWT encryption bundle.
     */
    public function initializeIv(int $ivLength): IvHandlerResult;

    /**
     * Validates the IV stored in the JWT encryption bundle against the expected length.
     */
    public function validateIv(string $iv, int $expected): void;
}
