<?php

declare(strict_types=1);

namespace Tests\phpunit\Token\Factory;

use DateTimeImmutable;
use DateTimeZone;
use Phithi92\JsonWebToken\Token\Factory\JwtTokenFactory;
use Phithi92\JsonWebToken\Token\JwtPayload;
use Tests\phpunit\TestCaseWithSecrets;

class JwtTokenFactoryTest extends TestCaseWithSecrets
{
    public function testReissueUsesCurrentReferenceTimeWithOriginalTimezone(): void
    {
        $timezone = new DateTimeZone('Europe/Berlin');
        $referenceTime = new DateTimeImmutable('-1 day', $timezone);

        $payload = (new JwtPayload($referenceTime))
            ->setExpiration('+2 days');

        $bundle = JwtTokenFactory::createToken('HS256', $this->manager, $payload);
        $originalExpiration = $bundle->getPayload()->getExpiration();

        $reissued = JwtTokenFactory::reissueBundle('+2 days', $bundle, $this->manager);
        $newPayload = $reissued->getPayload();

        $referenceTimezone = $newPayload->getDateClaimHelper()->getReferenceTime()->getTimezone()->getName();
        $this->assertSame($timezone->getName(), $referenceTimezone);

        $this->assertGreaterThan($originalExpiration, (int) $newPayload->getExpiration());

        $expectedLowerBound = (new DateTimeImmutable('now', $timezone))->modify('+2 days -5 seconds')->getTimestamp();
        $expectedUpperBound = (new DateTimeImmutable('now', $timezone))->modify('+2 days +5 seconds')->getTimestamp();

        $this->assertGreaterThanOrEqual($expectedLowerBound, (int) $newPayload->getExpiration());
        $this->assertLessThanOrEqual($expectedUpperBound, (int) $newPayload->getExpiration());
    }
}
