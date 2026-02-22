<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Factory;

use Phithi92\JsonWebToken\Token\Factory\JwtTokenServiceFactory;
use Phithi92\JsonWebToken\Token\Issuer\JwtTokenReissuer;
use Phithi92\JsonWebToken\Token\Reader\JwtTokenReader;
use Phithi92\JsonWebToken\Token\Service\JwtClaimsValidationService;
use Phithi92\JsonWebToken\Token\Service\JwtTokenCreator;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use PHPUnit\Framework\TestCase;
use ReflectionObject;

final class JwtTokenServiceFactoryTest extends TestCase
{
    public function testCreateDefaultReturnsJwtTokenService(): void
    {
        $service = JwtTokenServiceFactory::createDefault();

        self::assertInstanceOf(JwtTokenService::class, $service);
    }

    public function testCreateDefaultWiresDependencies(): void
    {
        $service = JwtTokenServiceFactory::createDefault();

        // We assert the internal wiring without calling crypto routines.
        $creator         = $this->getPrivateProperty($service, 'creator');
        $reader          = $this->getPrivateProperty($service, 'reader');
        $claimsValidator = $this->getPrivateProperty($service, 'claimsValidator');
        $reissuer        = $this->getPrivateProperty($service, 'reissuer');

        self::assertInstanceOf(JwtTokenCreator::class, $creator);
        self::assertInstanceOf(JwtTokenReader::class, $reader);
        self::assertInstanceOf(JwtClaimsValidationService::class, $claimsValidator);
        self::assertInstanceOf(JwtTokenReissuer::class, $reissuer);
    }

    public function testCreateDefaultCreatesNewInstancesEachTime(): void
    {
        $a = JwtTokenServiceFactory::createDefault();
        $b = JwtTokenServiceFactory::createDefault();

        self::assertNotSame($a, $b);

        // Optional: ensure key internal services are not shared between instances
        self::assertNotSame(
            $this->getPrivateProperty($a, 'creator'),
            $this->getPrivateProperty($b, 'creator')
        );
        self::assertNotSame(
            $this->getPrivateProperty($a, 'reader'),
            $this->getPrivateProperty($b, 'reader')
        );
    }

    /**
     * @return mixed
     */
    private function getPrivateProperty(object $object, string $propertyName)
    {
        $ref = new ReflectionObject($object);

        // Walk up the class tree in case the property is defined on a parent class.
        while (!$ref->hasProperty($propertyName) && ($ref = $ref->getParentClass())) {
            // noop (loop condition updates $ref)
        }

        self::assertNotFalse($ref, sprintf('Could not reflect class for property "%s".', $propertyName));
        self::assertTrue($ref->hasProperty($propertyName), sprintf('Property "%s" not found.', $propertyName));

        $prop = $ref->getProperty($propertyName);
        $prop->setAccessible(true);

        return $prop->getValue($object);
    }
}
