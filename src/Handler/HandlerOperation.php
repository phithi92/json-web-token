<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Handler;

/**
 * Description of HandlerOperation
 *
 * @author phillipthiele
 */
enum HandlerOperation: string
{
    case Perform = 'perform';     // e.g. sign, encrypt, generate, transform
    case Reverse = 'reverse';     // e.g. verify, decrypt, extract, untransform
}
