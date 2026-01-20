<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Validator;

use PDO;
use PDOStatement;
use Phithi92\JsonWebToken\Token\Validator\PdoJwtIdValidator;
use PHPUnit\Framework\TestCase;

final class PdoJwtIdValidatorTest extends TestCase
{
    public function testIsAllowedReturnsTrueWhenNotDenied(): void
    {
        $statement = $this->createMock(PDOStatement::class);
        $statement->expects($this->once())
            ->method('execute')
            ->with(['jwt_id' => 'token-id', 'type' => 'deny']);
        $statement->expects($this->once())
            ->method('fetchColumn')
            ->willReturn(false);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($statement);

        $validator = new PdoJwtIdValidator($pdo);

        $this->assertTrue($validator->isAllowed('token-id'));
    }

    public function testIsAllowedReturnsFalseWhenDenied(): void
    {
        $statement = $this->createMock(PDOStatement::class);
        $statement->expects($this->once())
            ->method('execute')
            ->with(['jwt_id' => 'token-id', 'type' => 'deny']);
        $statement->expects($this->once())
            ->method('fetchColumn')
            ->willReturn(1);

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->willReturn($statement);

        $validator = new PdoJwtIdValidator($pdo);

        $this->assertFalse($validator->isAllowed('token-id'));
    }

    public function testAllowStoresJwtId(): void
    {
        $statement = $this->createMock(PDOStatement::class);
        $statement->expects($this->once())
            ->method('execute')
            ->with($this->callback(function (array $params): bool {
                return $params['jwt_id'] === 'token-id'
                    && $params['type'] === 'allow'
                    && isset($params['expires_at']);
            }));

        $pdo = $this->createMock(PDO::class);
        $pdo->expects($this->once())
            ->method('prepare')
            ->with($this->stringContains('INSERT INTO jwt_id_list'))
            ->willReturn($statement);

        $validator = new PdoJwtIdValidator($pdo, true);

        $validator->allow('token-id', 60);
    }
}
