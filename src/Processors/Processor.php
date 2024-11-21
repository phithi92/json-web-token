<?php

namespace Phithi92\JsonWebToken\Processors;

use Phithi92\JsonWebToken\Processors\ProcessorInterface;
use Phithi92\JsonWebToken\Cryptographys\Provider;
use Phithi92\JsonWebToken\JwtAlgorithmManager;

/**
 * Abstract class Processor, implementing ProcessorInterface, which provides
 * management of JWT algorithms through an instance of JwtAlgorithmManager
 * and cryptographic operations via a Provider instance.
 *
 * This class initializes the algorithm manager through the constructor and
 * offers access to both the algorithm manager and provider instances via
 * `getManager()` and `getProvider()` methods.
 *
 * @package Phithi92\JsonWebToken\Processors
 */
abstract class Processor implements ProcessorInterface
{
    /**
     * Instance of Provider used for cryptographic operations.
     *
     * @var Provider
     */
    private Provider $provider;

    /**
     * Instance of JwtAlgorithmManager used to manage JWT algorithms.
     *
     * @var JwtAlgorithmManager
     */
    private readonly JwtAlgorithmManager $manager;

    /**
     * Constructor that sets the algorithm manager.
     *
     * @param JwtAlgorithmManager $manager Instance of JwtAlgorithmManager for managing JWT algorithms.
     */
    public function __construct(JwtAlgorithmManager $manager)
    {
        $this->manager = $manager;
    }

    /**
     * Returns the instance of the algorithm manager.
     *
     * @return JwtAlgorithmManager The JwtAlgorithmManager instance.
     */
    public function getManager(): JwtAlgorithmManager
    {
        return $this->manager;
    }

    /**
     * Returns the instance of the provider used for cryptographic operations.
     *
     * @return Provider The Provider instance.
     */
    public function getProvider(): Provider
    {
        return $this->provider;
    }

    /**
     * Sets the provider instance used for cryptographic operations.
     *
     * @param  Provider $provider The instance of Provider.
     * @return self
     */
    public function setProvider(Provider $provider): self
    {
        $this->provider = $provider;
        return $this;
    }
}
