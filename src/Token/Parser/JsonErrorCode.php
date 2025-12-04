<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Parser;

use Exception;
use Phithi92\JsonWebToken\Exceptions\Json\InvalidDepthException;
use Phithi92\JsonWebToken\Exceptions\Json\MalformedException;
use Phithi92\JsonWebToken\Exceptions\Json\MalformedUtf8Exception;

enum JsonErrorCode: int
{
    case SYNTAX = JSON_ERROR_SYNTAX;
    case CTRL = JSON_ERROR_CTRL_CHAR;
    case STATE = JSON_ERROR_STATE_MISMATCH;
    case UTF8 = JSON_ERROR_UTF8;
    case DEPTH = JSON_ERROR_DEPTH;

    public function toException(?int $depth): Exception
    {
        return match ($this) {
            self::SYNTAX,
            self::CTRL,
            self::STATE => new MalformedException(),
            self::UTF8 => new MalformedUtf8Exception(),
            self::DEPTH => new InvalidDepthException($depth ?? 0),
        };
    }
}
