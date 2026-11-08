<?php

namespace Tests\Profiler;

require_once __DIR__ . '/../../vendor/autoload.php';

use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Tests\Helpers\KeyProvider;

$algorithm = 'HS256';
$configArray = KeyProvider::getKey($algorithm);

// ----

$manager = new JwtKeyManager();
$manager->addPassphrase($configArray['passphrase'], $algorithm);

$service = new JwtTokenService(new JwtValidator());

echo $service->createTokenStringFromArray($algorithm, $manager, [
    'iat' => time(),
    'exp' => time() + 3600
]);
