<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Security;

enum KeyRole: string
{
    case Private = 'private';
    case Public = 'public';
}
