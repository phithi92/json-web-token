<?php

namespace Phithi92\JsonWebToken\Processors;

use Phithi92\JsonWebToken\JwtTokenContainer;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

interface ProcessorInterface
{
    public const JWT_TYPE = '';
    public function __construct(JwtAlgorithmManager $manager);
    public function verify(JwtTokenContainer $token): void;
    public function encrypt(JwtTokenContainer $token): JwtTokenContainer;
    public function decrypt(JwtTokenContainer $token): JwtTokenContainer;
    public function assemble(JwtTokenContainer $token): string;
    public function parse(string|array $token): JwtTokenContainer;
    public static function isSupported(string $algorithm): bool;
    public function getTokenType(): string;
}
