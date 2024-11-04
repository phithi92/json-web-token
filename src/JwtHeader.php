<?php

namespace Phithi92\JsonWebToken;

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Utilities\JsonEncoder;

/**
 * Description of Header
 *
 * @author phillip
 */
class JwtHeader
{
    private string $typ = '';
    private string $algorithm = '';
    private string $enc = '';

    public function __construct(?JwtAlgorithmManager $manager = null)
    {
        if ($manager !== null) {
            $this->setAlgorithm($manager->getAlgorithm());
            $this->setType($manager->getTokenType());
        }
    }

    public function setType(string $type): self
    {
        $this->typ = $type;
        return $this;
    }

    public function getType(): string
    {
        return $this->typ;
    }

    public function setAlgorithm(string $alorithm): self
    {
        $this->algorithm = $alorithm;
        return $this;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function setEnc(string $enc): self
    {
        $this->enc = $enc;
        return $this;
    }

    public function getEnc(): string
    {
        return $this->enc;
    }

    public function toArray(): array
    {
        $header = [
            'alg' => $this->getAlgorithm(),
            'typ' => $this->getType(),
        ];

        // Bedingte Zuweisung direkt im Array, um den Code kompakter zu halten
        if ($header['typ'] === 'JWS') {
            $header['enc'] = $this->getEnc();
        }

        return $header;
    }

    public function toJson(): string
    {
        return JsonEncoder::encode($this->toArray());
    }

    public static function fromJson(string $json): self
    {
        $header = JsonEncoder::decode($json);

        $self = new self();

        if (isset($header['enc'])) {
            $self->setEnc($header['enc']);
        }

        if (isset($header['alg'])) {
            $self->setAlgorithm($header['alg']);
        }
        if (isset($header['typ'])) {
            $self->setType($header['typ']);
        }

        return $self;
    }
}
