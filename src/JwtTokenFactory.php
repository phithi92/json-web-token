<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\Service\SignatureToken;
use Phithi92\JsonWebToken\Service\EncodingToken;
use Phithi92\JsonWebToken\JwtPayload;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Utilities\Base64UrlEncoder;
use Phithi92\JsonWebToken\Exception\Token\SignatureInvalid;
use Phithi92\JsonWebToken\Exception\Token\FormatInvalid;

/**
 * JsonWebToken is a final class responsible for creating, validating,
 * and managing JSON Web Tokens (JWTs), including JWS (JSON Web Signature)
 * and JWE (JSON Web Encryption) types. It supports token generation,
 * algorithm selection, and encoding/decoding of JWT structures.
 *
 * Note: The token structure is validated within this class, while the
 * content of the payload itself is validated only when the `toArray`
 * method of the JwtTokenContainer class is called.
 *
 * Key functionalities include:
 * - Creating JWTs (JWS or JWE) with support for various algorithms.
 * - Handling Base64URL encoding and decoding for JWT components.
 *
 * This class enforces the JWT standards RFC 7515 (JWS) and RFC 7516 (JWE),
 * and utilizes OpenSSL for cryptographic operations. It throws exceptions for
 * malformed tokens or cryptographic errors.
 *
 * @throws Specific exceptions provide clear messages for JWT-related issues.
 *
 * @autor Phillip Thiele <development@phillip-thiele.de>
 */
final class JwtTokenFactory
{
    /**
     * Constructor that initializes the JwtAlgorithmManager used for encoding and decoding.
     */
    public function __construct(private JwtAlgorithmManager $cipher)
    {
    }

    /**
     * Generates a JWT based on the given payload, selecting either JWS or JWE.
     *
     * This method uses the payload and algorithm manager to create a signed or encrypted JWT.
     *
     * @param  JwtPayload $payload The data for the token payload.
     * @return string The generated JWT string.
     */
    public function create(JwtPayload $payload): string
    {
        $token = new JwtTokenContainer($payload);
        $token->setHeader(new JwtHeader($this->cipher));

        // Choose the appropriate builder for JWS or JWE
        if ($token->getHeader()->getType() === 'JWS') {
            $builder = new SignatureToken($this->cipher);
        } else {
            $builder = new EncodingToken($this->cipher);
        }

        $tokenContainer = $builder->create($token);

        return $this->generateToken($tokenContainer);
    }

    /**
     * Encodes and combines the token parts into the final JWT string.
     *
     * This method assembles the token's header, payload, and optional encryption/authentication
     * components into a standard JWT format.
     *
     * @param  JwtTokenContainer $token The container holding the token data.
     * @return string The complete JWT string.
     */
    public function generateToken(JwtTokenContainer $token): string
    {
        $type = $token->getHeader()->getType();

        switch ($type) :
            case 'JWS':
                return $this->generateJwsToken($token);
            case 'JWE':
                return $this->generateJweToken($token);
        endswitch;
    }

    public function decrypt(string $encodingToken): JwtTokenContainer
    {
        $token = $this->hydrateJwtContainerFromString($encodingToken);

        switch ($token->getHeader()->getType()) :
            case 'JWS':
                $manager = new SignatureToken($this->cipher);
                break;

            case 'JWE':
                $manager = new EncodingToken($this->cipher);
                break;
        endswitch;

        $manager->decrypt($token);

        if (! $manager->verify($token, $manager)) {
            throw new SignatureInvalid();
        }

        return $token;
    }

    public function refreshToken(string $encodingToken, string $expirationInterval = '+1 hour'): string
    {
        $token = $this->decrypt($encodingToken);

        $token->getPayload()->setIssuedAt($expirationInterval);
        $token->getPayload()->setExpiration($expirationInterval);

        return $this->create($token->getPayload());
    }

    /**
     * Static method to create a JWT. Initializes a new instance and calls the create method.
     *
     * @param  JwtAlgorithmManager $algorithm The algorithm manager used for token generation.
     * @param  JwtPayload          $payload   The payload data to be included in the token.
     * @return string The generated JWT as a string.
     */
    public static function createToken(JwtAlgorithmManager $algorithm, JwtPayload $payload): string
    {
        return (new self($algorithm))->create($payload);
    }

    /**
     * Static method to validate a JWT. Initializes a new instance and calls the validate method.
     *
     * @param  JwtAlgorithmManager $algorithm The algorithm manager used for token validation.
     * @param  JwtPayload          $payload   The payload data to be validated in the token.
     * @return bool True if the token is valid, false otherwise.
     */
    public static function validateToken(JwtAlgorithmManager $algorithm, JwtPayload $payload): bool
    {
        return (new self($algorithm))->validate($payload);
    }

    private function hydrateJwtContainerFromString(string $encodingToken): JwtTokenContainer
    {
        $tokenData = explode('.', $encodingToken);

        if (count($tokenData) < 3) {
            throw new FormatInvalid();
        }

        $headerDecoded = Base64UrlEncoder::decode($tokenData[0]);
        $jwtHeader = JwtHeader::fromJson($headerDecoded);

        $token = (new JwtTokenContainer())->setHeader($jwtHeader);
        $type = $token->getHeader()->getType();

        if ($type === 'JWS') {
            if (count($tokenData) !== 3) {
                throw new FormatInvalid();
            }
            $payloadDecoded = Base64UrlEncoder::decode($tokenData[1]);
            $signatureDecoded = Base64UrlEncoder::decode($tokenData[2]);

            $token->setPayload(JwtPayload::fromJson($payloadDecoded))
                ->setSignature($signatureDecoded);
        } elseif ($type === 'JWE') {
            if (count($tokenData) !== 5) {
                throw new FormatInvalid();
            }
            $ivDecoded = Base64UrlEncoder::decode($tokenData[1]);
            $encryptedKeyDecoded = Base64UrlEncoder::decode($tokenData[2]);
            $encryptedPayloadDecoded = Base64UrlEncoder::decode($tokenData[3]);
            $authTagDecoded = Base64UrlEncoder::decode($tokenData[4]);

            $token->setIv($ivDecoded)
                ->setEncryptedKey($encryptedKeyDecoded)
                ->setEncryptedPayload($encryptedPayloadDecoded)
                ->setAuthTag($authTagDecoded);
        } else {
            throw new FormatInvalid();
        }

        return $token;
    }

    private function generateJwsToken(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedPayload = Base64UrlEncoder::encode($token->getPayload()->toJson());
        $encodedSignature = Base64UrlEncoder::encode($token->getSignature());
        return "$encodedHeader.$encodedPayload.$encodedSignature";
    }

    private function generateJweToken(JwtTokenContainer $token): string
    {
        $encodedHeader = Base64UrlEncoder::encode($token->getHeader()->toJson());
        $encodedIv = Base64UrlEncoder::encode($token->getIv() ?? '');
        $encodedCek = Base64UrlEncoder::encode($token->getEncryptedKey() ?? $token->getCek());
        $encodedPayload = Base64UrlEncoder::encode($token->getEncryptedPayload());
        $encodedAuthTag = Base64UrlEncoder::encode($token->getAuthTag());
        return "$encodedHeader.$encodedIv.$encodedCek.$encodedPayload.$encodedAuthTag";
    }
}
