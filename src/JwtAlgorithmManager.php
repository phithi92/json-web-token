<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Exception\InvalidArgument;
use ReflectionClass;

/**
 * Description of JwtAlgorithmManager
 *
 * @author phillip
 */
class JwtAlgorithmManager
{
    private string $algorithm;
    private string $tokenType; // JWS oder JWE
    private ?string $passphrase;
    private ?string $publicKey = null;
    private ?string $privateKey = null;

    private static array $jwsAlgorithms = [];
    private static array $jweAlgorithms = [];

    /**
     * Konstruktor für symmetrische oder asymmetrische Algorithmen.
     *
     * @param string      $algorithm  Der Name des Algorithmus (z.B. HS256, RS256, RSA-OAEP).
     * @param string|null $passphrase Für symmetrische Algorithmen (optional).
     * @param string|null $publicKey  Für asymmetrische Algorithmen
     *                                (optional).
     * @param string|null $privateKey Für asymmetrische Algorithmen (optional).
     */
    public function __construct(
        string $algorithm,
        ?string $passphrase = null,
        ?string $publicKey = null,
        ?string $privateKey = null
    ) {
        if ($passphrase === null && ($publicKey === null || $privateKey === null)) {
            throw new InvalidArgument('passphrase or public and private key needed');
        }

        $this->algorithm = $algorithm;
        $this->passphrase = $passphrase;
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->tokenType = $this->determineTokenType($algorithm);
    }

    public static function getJwsAlgorithms(): array
    {
        if (empty(self::$jwsAlgorithms)) {
            self::$jwsAlgorithms = (new ReflectionClass(Service\SignatureToken::class))->getConstants();
        }

        return self::$jwsAlgorithms;
    }

    public function getJweAlgorithms(): array
    {
        if (empty(self::$jweAlgorithms)) {
            self::$jweAlgorithms = (new ReflectionClass(Service\EncodingToken::class))->getConstants();
        }

        return self::$jweAlgorithms;
    }

    /**
     * Bestimmt den Token-Typ (JWS oder JWE) basierend auf dem Algorithmus.
     *
     * @param  string $algorithm Der verwendete Algorithmus.
     * @return string Der Token-Typ ('JWS' oder 'JWE').
     */
    private function determineTokenType(string $algorithm): string
    {
        if (in_array($algorithm, self::getJwsAlgorithms())) {
            return 'JWS'; // Signiertes Token
        } elseif (in_array($algorithm, self::getJweAlgorithms())) {
            return 'JWE'; // Verschlüsseltes Token
        }
    }

    /**
     * Gibt den Algorithmus zurück.
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * Gibt den symmetrischen Schlüssel zurück.
     */
    public function getPassphrase(): ?string
    {
        return $this->passphrase;
    }

    /**
     * Gibt den öffentlichen Schlüssel zurück (für asymmetrische Algorithmen).
     */
    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    /**
     * Gibt den privaten Schlüssel zurück (für asymmetrische Algorithmen).
     */
    public function getPrivateKey(): ?string
    {
        return $this->privateKey;
    }

    public function getTokenType(): ?string
    {
        return $this->tokenType;
    }
}
