<?php

declare(strict_types=1);

$envPath = getenv('KEYS_PATH');
$defaultPath = __DIR__ . '/../tests/keys';
$basePath = ($envPath !== false && $envPath !== '') ? $envPath : $defaultPath;
$basePath = rtrim($basePath, "/\\"); // Windows + Unix path normalization

if (!is_dir($basePath) && !mkdir($basePath, 0700, true) && !is_dir($basePath)) {
    fwrite(STDERR, "❌ Error: Failed to create base directory '{$basePath}'.\n");
    exit(1);
}

$distinguishedNames = [
    'countryName' => 'DE',
    'stateOrProvinceName' => 'NRW',
    'localityName' => 'Cologne',
    'organizationName' => 'MyOrg',
    'organizationalUnitName' => 'Dev',
    'commonName' => 'localhost',
    'emailAddress' => 'info@example.com',
];

// === RSA Key Generation ===
$rsaKeyLengths = [2048, 3072, 4096];

foreach ($rsaKeyLengths as $bits) {
    echo "🔐 Generating RSA key pair with {$bits} bits...\n";

    $keyPath = "{$basePath}/rsa/{$bits}";

    if (!is_dir($keyPath) && !mkdir($keyPath, 0700, true) && !is_dir($keyPath)) {
        echo "❌ Error: Failed to create directory '{$keyPath}'.\n";
        continue;
    }

    $privateKeyFile = "{$keyPath}/private.pem";
    $publicKeyFile = "{$keyPath}/public.pem";
    $certFile = "{$keyPath}/cert.pem";

    $config = [
        'private_key_bits' => $bits,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $privateKey = openssl_pkey_new($config);
    if (!$privateKey) {
        echo "❌ Error generating private RSA key ({$bits} bits): " . openssl_error_string() . "\n";
        continue;
    }

    $csr = openssl_csr_new($distinguishedNames, $privateKey, $config);
    if (!$csr) {
        echo '❌ Error in openssl_csr_new(): ' . openssl_error_string() . "\n";
        continue;
    }

    $cert = openssl_csr_sign($csr, null, $privateKey, 365);
    if (!$cert) {
        echo '❌ Error in openssl_csr_sign(): ' . openssl_error_string() . "\n";
        continue;
    }

    if (!openssl_pkey_export_to_file($privateKey, $privateKeyFile)) {
        echo "❌ Error exporting private key to file: {$privateKeyFile}\n";
        continue;
    }

    if (!openssl_x509_export_to_file($cert, $certFile)) {
        echo "❌ Error exporting certificate to file: {$certFile}\n";
        continue;
    }

    $details = openssl_pkey_get_details($privateKey);
    if (!file_put_contents($publicKeyFile, $details['key'], LOCK_EX)) {
        echo "❌ Error writing public key to file: {$publicKeyFile}\n";
        continue;
    }

    echo "✅ RSA {$bits}-bit key pair and certificate stored in {$keyPath}\n\n";
}

// === EC Key Generation ===
$ecCurves = [
    'prime256v1' => 'es256', // ES256
    'secp384r1' => 'es384', // ES384
    'secp521r1' => 'es512', // ES512
];

foreach ($ecCurves as $curve => $hash) {
    echo "🔐 Generating EC key pair for curve: {$curve}...\n";

    $keyPath = "{$basePath}/ec/{$curve}";

    if (!is_dir($keyPath) && !mkdir($keyPath, 0700, true) && !is_dir($keyPath)) {
        echo "❌ Error: Failed to create directory '{$keyPath}'.\n";
        continue;
    }

    $privateKeyFile = "{$keyPath}/private.pem";
    $publicKeyFile = "{$keyPath}/public.pem";
    $certFile = "{$keyPath}/cert.pem";

    $config = [
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => $curve,
    ];

    $privateKey = openssl_pkey_new($config);
    if (!$privateKey) {
        echo "❌ Error generating private EC key ({$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    $csr = openssl_csr_new($distinguishedNames, $privateKey, $config);
    if (!$csr) {
        echo "❌ Error in openssl_csr_new() (EC {$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    $cert = openssl_csr_sign($csr, null, $privateKey, 365);
    if (!$cert) {
        echo "❌ Error in openssl_csr_sign() (EC {$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    if (!openssl_pkey_export_to_file($privateKey, $privateKeyFile)) {
        echo "❌ Error exporting private EC key to file: {$privateKeyFile}\n";
        continue;
    }

    if (!openssl_x509_export_to_file($cert, $certFile)) {
        echo "❌ Error exporting EC certificate to file: {$certFile}\n";
        continue;
    }

    $details = openssl_pkey_get_details($privateKey);
    if (!file_put_contents($publicKeyFile, $details['key'], LOCK_EX)) {
        echo "❌ Error writing public EC key to file: {$publicKeyFile}\n";
        continue;
    }

    echo "✅ EC key pair for {$curve} stored in {$keyPath}\n\n";
}

// === AES-GCM Key Generation ===
$aesGcmConfigs = [
    'a128gcm' => 16, // 128 Bit = 16 Byte
    'a192gcm' => 24, // 192 Bit = 24 Byte
    'a256gcm' => 32, // 256 Bit = 32 Byte
];

foreach ($aesGcmConfigs as $algo => $bytes) {
    echo "🔐 Generating AES-GCM key for {$algo} ({$bytes} bytes)...\n";

    $keyPath = "{$basePath}/aes/{$algo}";

    if (!is_dir($keyPath) && !mkdir($keyPath, 0700, true) && !is_dir($keyPath)) {
        echo "❌ Error: Failed to create directory '{$keyPath}'.\n";
        continue;
    }

    $keyFile = "{$keyPath}/secret.key";
    $key = random_bytes($bytes);

    if (!file_put_contents($keyFile, $key, LOCK_EX)) {
        echo "❌ Error writing AES-GCM key to file: {$keyFile}\n";
        continue;
    }

    echo "✅ AES-GCM key stored in {$keyFile}\n\n";
}

// === HMAC Key Generation ===
$hmacConfigs = [
    'hs256' => 32, // 256 Bit
    'hs384' => 48, // 384 Bit
    'hs512' => 64, // 512 Bit
];

foreach ($hmacConfigs as $algo => $bytes) {
    echo "🔐 Generating HMAC key for {$algo} ({$bytes} bytes)...\n";

    $keyPath = "{$basePath}/hmac/{$algo}";

    if (!is_dir($keyPath) && !mkdir($keyPath, 0700, true) && !is_dir($keyPath)) {
        echo "❌ Error: Failed to create directory '{$keyPath}'.\n";
        continue;
    }

    $keyFile = "{$keyPath}/secret.key";
    $key = random_bytes($bytes);

    if (!file_put_contents($keyFile, $key, LOCK_EX)) {
        echo "❌ Error writing HMAC key to file: {$keyFile}\n";
        continue;
    }

    echo "✅ HMAC key stored in {$keyFile}\n\n";
}

echo "🎉 All keys for RSA, EC, AES-GCM and HMAC have been successfully generated.\n";
