<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Client\ClientAuthenticator;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Starts Device Sign-In (RFC 8628 §3.1–3.2, Poppy 0.2 4.6).
 *
 * No DPoP proof here: the request carries no token (4.3). The Personal Agent's
 * key comes in when it polls the token endpoint.
 */
final readonly class DeviceAuthorizationEndpoint
{
    /** A fresh user code that collides with a pending one is drawn again; this many times at most. */
    private const USER_CODE_ATTEMPTS = 5;

    public function __construct(
        private ServerConfiguration $configuration,
        private PoppyStorage $storage,
        private ClientAuthenticator $clients,
        private JsonResponder $responder,
        private ClockInterface $clock,
        private RateLimiter $rateLimiter = new NoRateLimit(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            return $this->responder->json($this->process($request));
        } catch (PoppyError $error) {
            return $this->responder->error($error);
        }
    }

    /** @return array<string, mixed> */
    private function process(ServerRequestInterface $request): array
    {
        if (!$this->configuration->hasDeviceSignIn()) {
            throw PoppyError::unsupportedGrantType();
        }
        if ($request->getMethod() !== 'POST') {
            throw PoppyError::invalidRequest('The device authorization endpoint accepts POST only.');
        }

        $parameters = FormParameters::from($request);

        $retryAfter = $this->rateLimiter->hit('device', $parameters['client_id'] ?? 'unidentified');
        if ($retryAfter !== null) {
            throw PoppyError::rateLimited($retryAfter);
        }

        $client = $this->clients->authenticate($parameters);
        $scopes = Scopes::parse($parameters['scope'] ?? null, $this->configuration->deviceScopes ?? []);

        $deviceCode = Secrets::token('pdc_');
        $userCode = $this->freshUserCode();
        $ttl = $this->configuration->deviceCodeTtl;
        $interval = $this->configuration->deviceInterval;

        $this->storage->saveDeviceAuthorization(new DeviceAuthorization(
            Secrets::hash($deviceCode),
            $userCode,
            $client->clientId(),
            $scopes,
            $this->clock->now()->modify('+' . $ttl . ' seconds'),
            $interval,
        ));

        $verificationUri = $this->configuration->endpoints->deviceVerification;

        return [
            'device_code' => $deviceCode,
            'user_code' => $userCode,
            'verification_uri' => $verificationUri,
            'verification_uri_complete' => $verificationUri . (str_contains($verificationUri, '?') ? '&' : '?') . 'user_code=' . rawurlencode($userCode),
            'expires_in' => $ttl,
            'interval' => $interval,
        ];
    }

    private function freshUserCode(): string
    {
        $now = $this->clock->now();
        for ($attempt = 0; $attempt < self::USER_CODE_ATTEMPTS; ++$attempt) {
            $code = Secrets::userCode();
            $existing = $this->storage->findDeviceAuthorizationByUserCode($code);
            if ($existing === null || $existing->isExpired($now)) {
                return $code;
            }
        }

        throw PoppyError::rateLimited(5);
    }
}
