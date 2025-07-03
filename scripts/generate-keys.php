<?php

$keyLengths = [2048, 3072, 4096];
$basePath = dirname(__DIR__) . '/../tests/keys/'; // Projektverzeichnis

foreach ($keyLengths as $bits) {
    echo "Generiere RSA-Schlüssel mit $bits Bit...\n";

    $privateKeyFile = "$basePath/$bits/private.pem";
    $publicKeyFile  = "$basePath/$bits/public.pem";
    $certFile       = "$basePath/$bits/cert.pem";

    $config = [
        "private_key_bits" => $bits,
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
    ];

    // Schlüssel generieren
    $privateKey = openssl_pkey_new($config);
    if (!$privateKey) {
        echo "Fehler beim Erzeugen des privaten Schlüssels ($bits Bit).\n";
        continue;
    }

    // CSR-Daten
    $dn = [
        "countryName"            => "DE",
        "stateOrProvinceName"    => "NRW",
        "localityName"           => "",
        "organizationName"       => "",
        "organizationalUnitName" => "",
        "commonName"             => "localhost",
        "emailAddress"           => "info@example.com"
    ];

    // Zertifikatsanforderung
    $csr = openssl_csr_new($dn, $privateKey, $config);
    if (!$csr) {
        echo "Fehler beim Erzeugen der CSR ($bits Bit).\n";
        continue;
    }

    // Selbstsigniertes Zertifikat für 1 Jahr
    $cert = openssl_csr_sign($csr, null, $privateKey, 365);
    if (!$cert) {
        echo "Fehler beim Erzeugen des Zertifikats ($bits Bit).\n";
        continue;
    }

    // Private Key speichern
    openssl_pkey_export_to_file($privateKey, $privateKeyFile);

    // Zertifikat speichern
    openssl_x509_export_to_file($cert, $certFile);

    // Öffentlichen Schlüssel extrahieren und speichern
    $keyDetails = openssl_pkey_get_details($privateKey);
    file_put_contents($publicKeyFile, $keyDetails['key']);

    echo "✅ RSA $bits-Bit Schlüssel und Zertifikat generiert.\n\n";
}

echo "Alle Schlüssel wurden erstellt.\n";
