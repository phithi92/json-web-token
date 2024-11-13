<?php

require_once __DIR__ . '/TestCaseWithSecrets.php';

use Phithi92\JsonWebToken\JwtAlgorithmManager;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingPassphraseException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\MissingKeysException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\UnsupportedAlgorithmException;
use Phithi92\JsonWebToken\Exceptions\Cryptographys\InvalidAsymetricKeyException;

class JwtAlgorithmManagerTest extends TestCaseWithSecrets
{    
    public function testConstructorWithSymmetricAlgorithmAndPassphrase()
    {
        $manager = new JwtAlgorithmManager('HS256', 'testpassphrase');
        $this->assertEquals('HS256', $manager->getAlgorithm());
        $this->assertEquals('testpassphrase', $manager->getPassphrase());
        $this->assertNull($manager->getPublicKey());
        $this->assertNull($manager->getPrivateKey());
    }

    public function testConstructorThrowsExceptionWithoutPassphraseOrKeys()
    {
        $this->expectException(MissingPassphraseException::class);

        new JwtAlgorithmManager('HS256');
    }
    
    public function testConstructorThrowsExceptionWithEmptyPassphrase()
    {
        $this->expectException(MissingPassphraseException::class);

        new JwtAlgorithmManager('HS256','');
    }

    public function testConstructorWithIncompleteAsymmetricKeys()
    {
        $this->expectException(MissingKeysException::class);

        new JwtAlgorithmManager('RS256', null, $this->getPublicKey(2048), null);
    }
    
    public function testGettersWithOnlyPassphrase()
    {
        $manager = new JwtAlgorithmManager('HS256', 'secret');
        $this->assertEquals('HS256', $manager->getAlgorithm());
        $this->assertEquals('secret', $manager->getPassphrase());
        $this->assertNull($manager->getPublicKey());
        $this->assertNull($manager->getPrivateKey());
    }

    public function testEmptyPublicKeyWithAsymmetricAlgorithm()
    {
        $this->expectException(InvalidAsymetricKeyException::class);
        new JwtAlgorithmManager('RS256', null, '', 'privateKey');
    }

    public function testEmptyPrivateKeyWithAsymmetricAlgorithm()
    {
        $this->expectException(InvalidAsymetricKeyException::class);
        new JwtAlgorithmManager('RS256', null, 'publicKey', '');
    }
}
