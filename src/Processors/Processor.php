<?php

namespace Phithi92\JsonWebToken\Processors;

use Phithi92\JsonWebToken\Processors\ProcessorInterface;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

abstract class Processor implements ProcessorInterface
{
    private readonly JwtAlgorithmManager $manager;

    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->setManager($manager);
    }

    private function setManager(JwtAlgorithmManager $manager): self
    {
        $this->manager = $manager;
        return $this;
    }

    public function getManager(): JwtAlgorithmManager
    {
        return $this->manager;
    }
}
