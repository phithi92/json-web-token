<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Token\Validator;

use DateTimeImmutable;
use PDO;

final class PdoJwtIdValidator implements JwtIdRegistryInterface
{
    private const TYPE_DENY  = 'deny';
    private const TYPE_ALLOW = 'allow';

    private PDO $pdo;

    private bool $useAllowList;

    public function __construct(PDO $pdo, bool $useAllowList = false)
    {
        $this->pdo = $pdo;
        $this->useAllowList = $useAllowList;
    }

    public function isAllowed(?string $jwtId): bool
    {
        if ($jwtId === null) {
            return !$this->useAllowList;
        }

        if ($this->isDenied($jwtId)) {
            return false;
        }

        if ($this->useAllowList) {
            return $this->isAllowedExplicitly($jwtId);
        }

        return true;
    }

    public function deny(string $jwtId, int $ttl): void
    {
        $this->store(
            $jwtId,
            self::TYPE_DENY,
            $ttl
        );
    }

    public function allow(string $jwtId, int $ttl): void
    {
        $this->store(
            $jwtId,
            self::TYPE_ALLOW,
            $ttl
        );
    }

    private function isDenied(string $jwtId): bool
    {
        return $this->exists($jwtId, self::TYPE_DENY);
    }

    private function isAllowedExplicitly(string $jwtId): bool
    {
        return $this->exists($jwtId, self::TYPE_ALLOW);
    }

    private function exists(string $jwtId, string $type): bool
    {
        $stmt = $this->pdo->prepare(
            'SELECT 1
             FROM jwt_id_list
             WHERE jwt_id = :jwt_id
               AND type = :type
               AND expires_at > NOW()
             LIMIT 1'
        );

        $stmt->execute([
            'jwt_id' => $jwtId,
            'type'   => $type,
        ]);

        return $stmt->fetchColumn() !== false;
    }

    private function store(string $jwtId, string $type, int $ttl): void
    {
        $expiresAt = (new DateTimeImmutable())
            ->modify('+' . $ttl . ' seconds')
            ->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO jwt_id_list (jwt_id, type, expires_at)
             VALUES (:jwt_id, :type, :expires_at)
             ON DUPLICATE KEY UPDATE expires_at = :expires_at'
        );

        $stmt->execute([
            'jwt_id'     => $jwtId,
            'type'       => $type,
            'expires_at' => $expiresAt,
        ]);
    }
}
