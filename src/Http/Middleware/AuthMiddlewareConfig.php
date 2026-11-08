<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Http\Middleware;

class AuthMiddlewareConfig
{
    public string $headerName = 'Authorization';
    public string $tokenPrefix = 'Bearer ';
    public ?string $cookieName = null;
    public bool $allowOptional = false;
    public bool $returnJsonError = true;
    public int $unauthorizedStatus = 401;

    public function __construct(array $options = [])
    {
        foreach ($options as $key => $value) {
            if (property_exists($this, $key)) {
                $this->$key = $value;
            }
        }
    }
}
