<?php

declare(strict_types=1);

namespace Phithi92\JsonWebToken\Http\Middleware;

use Phithi92\JsonWebToken\Exceptions\Crypto\CryptoException;
use Phithi92\JsonWebToken\Exceptions\Payload\PayloadException;
use Phithi92\JsonWebToken\Exceptions\Security\PassphraseNotFoundException;
use Phithi92\JsonWebToken\Exceptions\Security\SecurityException;
use Phithi92\JsonWebToken\Exceptions\Token\TokenException;
use Phithi92\JsonWebToken\Exceptions\Token\UnresolvableKeyException;
use Phithi92\JsonWebToken\Security\KeyManagement\JwtKeyManager;
use Phithi92\JsonWebToken\Token\JwtBundle;
use Phithi92\JsonWebToken\Token\Service\JwtTokenService;
use Phithi92\JsonWebToken\Token\Validator\JwtValidator;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

use function str_contains;
use function strncasecmp;
use function substr;
use function trim;

final class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly JwtTokenService $tokenService,
        private readonly JwtKeyManager $keyManager,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly ?JwtValidator $validator = null,
        private readonly ?LoggerInterface $logger = null,
        private readonly string $headerName = 'Authorization',
        private readonly string $tokenAttribute = 'jwt_token',
        private readonly string $bundleAttribute = 'jwt_bundle',
        private readonly string $payloadAttribute = 'jwt_payload',
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->extractBearerToken($request);

        if ($token === null) {
            return $this->unauthorizedResponse('invalid_request');
        }

        try {
            $bundle = $this->tokenService->decryptToken($token, $this->keyManager, $this->validator);
        } catch (Throwable $e) {
            [$status, $type] = match (true) {
                $e instanceof UnresolvableKeyException || $e instanceof PassphraseNotFoundException => [500, 'server_error'],
                $e instanceof TokenException || $e instanceof PayloadException || $e instanceof CryptoException || $e instanceof SecurityException => [401, 'invalid_token'],
                default => throw $e
            };

            $this->logAuthenticationFailure($e->getMessage(), $type, $e);

            return $this->errorResponse($status, $type);
        }

        $this->logAuthenticationSuccess($bundle);

        return $handler->handle(
            $request
                ->withAttribute($this->tokenAttribute, $token)
                ->withAttribute($this->bundleAttribute, $bundle)
                ->withAttribute($this->payloadAttribute, $bundle->getPayload())
        );
    }

    /**
     * @return non-empty-string|null
     */
    private function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $headerValue = trim($request->getHeaderLine($this->headerName));

        if ($headerValue === '') {
            $this->logAuthenticationFailure('Bearer token missing.', 'invalid_request');

            return null;
        }

        if (strncasecmp($headerValue, 'Bearer ', 7) !== 0) {
            $this->logAuthenticationFailure('Authorization header is not a Bearer token.', 'invalid_request');

            return null;
        }

        $token = substr($headerValue, 7);

        if ($token === '' || str_contains($token, ' ')) {
            // ungültiger Token
        }

        return $token;
    }

    private function unauthorizedResponse(string $error): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse(401)
            ->withHeader('WWW-Authenticate', sprintf('Bearer error="%s"', $error));
    }

    private function logAuthenticationSuccess(JwtBundle $bundle): void
    {
        $header = $bundle->getHeader();

        $this->logger?->info(
            'JWT authentication succeeded.',
            [
                'header' => $this->headerName,
                'algorithm' => $header->getAlgorithm(),
                'kid' => $header->hasKid() ? $header->getKid() : null,
            ]
        );
    }

    private function logAuthenticationFailure(
        string $message,
        string $error,
        TokenException|PayloadException|CryptoException|SecurityException|UnresolvableKeyException|PassphraseNotFoundException|null $exception = null
    ): void {
        $context = [
            'header' => $this->headerName,
            'error' => $error,
        ];

        if ($exception !== null) {
            $context['exception'] = $exception::class;
            $context['message'] = $exception->getMessage();
        }

        $this->logger?->warning($message, $context);
    }
}
