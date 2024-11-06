<?php

use Phithi92\JsonWebToken\Exception\InvalidArgument;
use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exception\AlgorithmManager\UnsupportedAlgorithmException;

require_once __DIR__ . '/TestCaseWithSecrets.php';

class JwtAlgorithmManagerTest extends \TestCaseWithSecrets
{    
    public function testConstructorWithSymmetricAlgorithmAndPassphrase()
    {
        $manager = new JwtAlgorithmManager('HS256', 'testpassphrase');
        $this->assertEquals('HS256', $manager->getAlgorithm());
        $this->assertEquals('testpassphrase', $manager->getPassphrase());
        $this->assertNull($manager->getPublicKey());
        $this->assertNull($manager->getPrivateKey());
        $this->assertEquals('JWS', $manager->getTokenType());
    }

    public function testConstructorThrowsExceptionWithoutPassphraseOrKeys()
    {
        $this->expectException(InvalidArgument::class);

        new JwtAlgorithmManager('HS256');
    }

    public function testConstructorWithIncompleteAsymmetricKeys()
    {
        $this->expectException(InvalidArgument::class);

        new JwtAlgorithmManager('RS256', null, $this->publicKey2048, null);
    }
    
    public function testDetermineTokenTypeJWS()
    {
        $manager = new JwtAlgorithmManager('HS256', 'testpassphrase');
        $this->assertEquals('JWS', $manager->getTokenType());
    }

    public function testDetermineTokenTypeJWE()
    {
        $manager = new JwtAlgorithmManager('RSA-OAEP', null, $this->publicKey2048, $this->privateKey2048);
        $this->assertEquals('JWE', $manager->getTokenType());
    }

    public function testGettersWithOnlyPassphrase()
    {
        $manager = new JwtAlgorithmManager('HS256', 'secret');
        $this->assertEquals('HS256', $manager->getAlgorithm());
        $this->assertEquals('secret', $manager->getPassphrase());
        $this->assertNull($manager->getPublicKey());
        $this->assertNull($manager->getPrivateKey());
    }

    public function testInvalidAlgorithmThrowsException()
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        new JwtAlgorithmManager('INVALID', 'testpassphrase');
    }

    public function testEmptyPublicKeyWithAsymmetricAlgorithm()
    {
        $this->expectException(InvalidArgument::class);
        new JwtAlgorithmManager('RS256', null, '', 'privateKey');
    }

    public function testEmptyPrivateKeyWithAsymmetricAlgorithm()
    {
        $this->expectException(InvalidArgument::class);
        new JwtAlgorithmManager('RS256', null, 'publicKey', '');
    }
}
