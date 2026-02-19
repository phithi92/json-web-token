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
    'localityName' => 'Köln',
    'organizationName' => 'MyOrg',
    'organizationalUnitName' => 'Dev',
    'commonName' => 'localhost',
    'emailAddress' => 'info@example.com',
];

// === RSA Key Generation ===
$rsaKeyLengths = [2048, 3072, 4096];

foreach ($rsaKeyLengths as $bits) {
    echo "🔐 Generiere RSA-Schlüssel mit {$bits} Bit...\n";

    $keyPath = "{$basePath}/rsa/{$bits}";
    @mkdir($keyPath, 0777, true);

    $privateKeyFile = "{$keyPath}/private.pem";
    $publicKeyFile = "{$keyPath}/public.pem";
    $certFile = "{$keyPath}/cert.pem";

    $config = [
        'private_key_bits' => $bits,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];

    $privateKey = openssl_pkey_new($config);
    if (! $privateKey) {
        echo "❌ Fehler beim Erzeugen des privaten RSA-Schlüssels ({$bits} Bit): " . openssl_error_string() . "\n";
        continue;
    }

    $csr = openssl_csr_new($distinguishedNames, $privateKey, $config);
    if (! $csr) {
        echo '❌ Fehler bei openssl_csr_new(): ' . openssl_error_string() . "\n";
        continue;
    }

    $cert = openssl_csr_sign($csr, null, $privateKey, 365);
    if (! $cert) {
        echo '❌ Fehler bei openssl_csr_sign(): ' . openssl_error_string() . "\n";
        continue;
    }

    openssl_pkey_export_to_file($privateKey, $privateKeyFile);
    openssl_x509_export_to_file($cert, $certFile);

    $details = openssl_pkey_get_details($privateKey);
    file_put_contents($publicKeyFile, $details['key']);

    echo "✅ RSA {$bits}-Bit Schlüssel und Zertifikat gespeichert unter {$keyPath}\n\n";
}

// === EC Key Generation ===
$ecCurves = [
    'prime256v1' => 'es256', // ES256
    'secp384r1' => 'es384', // ES384
    'secp521r1' => 'es512', // ES512
];

foreach ($ecCurves as $curve => $hash) {
    echo "🔐 Generiere EC-Schlüssel für Kurve: {$curve}...\n";

    $keyPath = "{$basePath}/ec/{$curve}";
    
    @mkdir($keyPath, 0777, true);

    $privateKeyFile = "{$keyPath}/private.pem";
    $publicKeyFile = "{$keyPath}/public.pem";
    $certFile = "{$keyPath}/cert.pem";

    $config = [
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => $curve,
    ];

    $privateKey = openssl_pkey_new($config);
    if (! $privateKey) {
        echo "❌ Fehler beim Erzeugen des privaten EC-Schlüssels ({$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    $csr = openssl_csr_new($distinguishedNames, $privateKey, $config);
    if (! $csr) {
        echo "❌ Fehler bei openssl_csr_new() (EC {$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    $cert = openssl_csr_sign($csr, null, $privateKey, 365);
    if (! $cert) {
        echo "❌ Fehler bei openssl_csr_sign() (EC {$curve}): " . openssl_error_string() . "\n";
        continue;
    }

    openssl_pkey_export_to_file($privateKey, $privateKeyFile);
    openssl_x509_export_to_file($cert, $certFile);

    $details = openssl_pkey_get_details($privateKey);
    file_put_contents($publicKeyFile, $details['key']);

    echo "✅ EC-Schlüssel für {$curve} gespeichert unter {$keyPath}\n\n";
}

// === AES-GCM Key Generation ===
$aesGcmConfigs = [
    'a128gcm' => 16, // 128 Bit = 16 Byte
    'a192gcm' => 24, // 192 Bit = 24 Byte
    'a256gcm' => 32, // 256 Bit = 32 Byte
];

foreach ($aesGcmConfigs as $algo => $bytes) {
    echo "🔐 Generiere AES-GCM-Schlüssel für {$algo} ({$bytes} Byte)...\n";

    $keyPath = "{$basePath}/aes/{$algo}";
    @mkdir($keyPath, 0777, true);

    $keyFile = "{$keyPath}/secret.key";
    $key = random_bytes($bytes);

    file_put_contents($keyFile, $key);

    echo "✅ AES-GCM-Schlüssel gespeichert unter {$keyFile}\n\n";
}

// === HMAC Key Generation ===
$hmacConfigs = [
    'hs256' => 32, // 256 Bit
    'hs384' => 48, // 384 Bit
    'hs512' => 64, // 512 Bit
];

foreach ($hmacConfigs as $algo => $bytes) {
    echo "🔐 Generiere HMAC-Schlüssel für {$algo} ({$bytes} Byte)...\n";

    $keyPath = "{$basePath}/hmac/{$algo}";
    @mkdir($keyPath, 0777, true);

    $keyFile = "{$keyPath}/secret.key";
    $key = random_bytes($bytes);

    file_put_contents($keyFile, $key);

    echo "✅ HMAC-Schlüssel gespeichert unter {$keyFile}\n\n";
}

echo "🎉 Alle Schlüssel für RSA, EC, AES-GCM und HMAC wurden erfolgreich generiert.\n";
