<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Assertion\SessionAssertionVerifier;
use Koh\Poppy\Client\AuthenticatedClient;
use Koh\Poppy\Client\ClientAuthenticator;
use Koh\Poppy\Dpop\DpopVerifier;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\TokenType;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The token endpoint (Poppy 0.2, 4.2 and 4.4–4.8).
 *
 * Every request authenticates the Personal Agent with a client assertion and,
 * unless it asks for a Bearer token for an MCP server without DPoP, proves
 * possession of a DPoP key; the token it gets is bound to that key. The four
 * grants:
 *
 * - `jwt-bearer` starts a signed-out Session, or renews one with `session_id`;
 * - `authorization_code` finishes Direct Sign-In for `session_id`;
 * - `device_code` finishes Device Sign-In for `session_id`;
 * - `refresh_token` uses an Account Token, for `session_id` or a new Session.
 */
final readonly class TokenEndpoint
{
    public const GRANT_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    public const GRANT_DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code';

    /** RFC 8628 §3.5: each slow_down adds five seconds to the interval. */
    private const SLOW_DOWN_STEP = 5;

    public function __construct(
        private ServerConfiguration $configuration,
        private PoppyStorage $storage,
        private ClientAuthenticator $clients,
        private SessionAssertionVerifier $sessionAssertions,
        private DpopVerifier $dpop,
        private TokenIssuer $issuer,
        private JsonResponder $responder,
        private ClockInterface $clock,
        private RateLimiter $rateLimiter = new NoRateLimit(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $body = $this->process($request);
        } catch (PoppyError $error) {
            return $this->responder->error($error);
        }

        $nonce = $this->dpop->nextNonce();

        return $this->responder->json($body, 200, $nonce !== null ? ['DPoP-Nonce' => $nonce] : []);
    }

    /** @return array<string, mixed> */
    private function process(ServerRequestInterface $request): array
    {
        if ($request->getMethod() !== 'POST') {
            throw PoppyError::invalidRequest('The token endpoint accepts POST only.');
        }

        $parameters = FormParameters::from($request);

        $retryAfter = $this->rateLimiter->hit('token', is_string($parameters['client_id'] ?? null) ? $parameters['client_id'] : 'unidentified');
        if ($retryAfter !== null) {
            throw PoppyError::rateLimited($retryAfter);
        }

        $client = $this->clients->authenticate($parameters);

        [$type, $resource] = $this->tokenTarget($parameters);
        $jkt = $type === TokenType::DPoP
            ? $this->dpop->verify($request, $this->configuration->endpoints->token, rejectReplays: true)->jkt
            : null;

        return match ($parameters['grant_type'] ?? null) {
            self::GRANT_JWT_BEARER => $this->jwtBearer($client, $parameters, $type, $jkt, $resource),
            'authorization_code' => $this->authorizationCode($client, $parameters, $type, $jkt, $resource),
            self::GRANT_DEVICE_CODE => $this->deviceCode($client, $parameters, $type, $jkt, $resource),
            'refresh_token' => $this->refreshToken($client, $parameters, $type, $jkt, $resource),
            default => throw PoppyError::unsupportedGrantType(),
        };
    }

    /**
     * The token type and resource a request asks for (4.3). Without `resource`
     * the token is a DPoP token for every service that has no resource of its
     * own. With one, it must name a listed API; an MCP server without DPoP
     * then gets a Bearer token, even if the request carried a proof.
     *
     * @param array<string, mixed> $parameters
     *
     * @return array{TokenType, ?string}
     */
    private function tokenTarget(array $parameters): array
    {
        $resource = $parameters['resource'] ?? null;
        if ($resource === null) {
            return [TokenType::DPoP, null];
        }
        if (!is_string($resource)) {
            throw PoppyError::invalidTarget('resource must be a single URL');
        }

        $api = $this->configuration->apiForResource($resource);
        if ($api === null) {
            throw PoppyError::invalidTarget('resource names no API of this Company');
        }

        return [$api->isMcp() && !$api->dpop ? TokenType::Bearer : TokenType::DPoP, $resource];
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private function jwtBearer(AuthenticatedClient $client, array $parameters, TokenType $type, ?string $jkt, ?string $resource): array
    {
        $assertion = $parameters['assertion'] ?? null;
        if (!is_string($assertion)) {
            throw PoppyError::invalidGrant('assertion is missing');
        }

        $userId = $this->sessionAssertions->verify($assertion, $client);

        // A signed-out token carries no account scopes, so any requested scope is unavailable.
        Scopes::parse($parameters['scope'] ?? null, [], required: false);

        $sessionId = $parameters['session_id'] ?? null;
        if ($sessionId === null) {
            $session = $this->issuer->startSession($client->clientId(), $userId);
        } else {
            $session = $this->activeSession($sessionId);
            if (!$session->belongsTo($client->clientId(), $userId)) {
                throw PoppyError::invalidSession();
            }
            if ($session->isSignedIn()) {
                throw PoppyError::invalidGrant('A signed-in Session is renewed with its Account Token.');
            }
        }

        return $this->issuer->sessionTokenResponse($session, $type, $jkt, $resource, []);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private function authorizationCode(AuthenticatedClient $client, array $parameters, TokenType $type, ?string $jkt, ?string $resource): array
    {
        $code = $parameters['code'] ?? null;
        $redirectUri = $parameters['redirect_uri'] ?? null;
        $verifier = $parameters['code_verifier'] ?? null;
        if (!is_string($code)) {
            throw PoppyError::invalidGrant('code is missing');
        }
        if (!is_string($redirectUri) || !is_string($verifier)) {
            throw PoppyError::invalidRequest('redirect_uri and code_verifier are required');
        }

        // Fetch the Session before the code is consumed, so a mistyped
        // session_id does not cost the User their sign-in.
        $session = $this->activeSession($parameters['session_id'] ?? null);

        $record = $this->storage->consumeAuthorizationCode(Secrets::hash($code));
        if ($record === null
            || $this->clock->now() >= $record->expiresAt
            || !hash_equals($record->clientId, $client->clientId())
            || $record->redirectUri !== $redirectUri
            || !Pkce::verify($verifier, $record->codeChallenge)) {
            throw PoppyError::invalidGrant('The code is unknown, expired, already used, or does not match this request.');
        }

        if (!hash_equals($session->clientId, $client->clientId())) {
            throw PoppyError::invalidSession();
        }

        return $this->signIn($session, $record->accountId, $record->scopes, $type, $jkt, $resource);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private function deviceCode(AuthenticatedClient $client, array $parameters, TokenType $type, ?string $jkt, ?string $resource): array
    {
        $deviceCode = $parameters['device_code'] ?? null;
        if (!is_string($deviceCode)) {
            throw PoppyError::invalidGrant('device_code is missing');
        }

        $hash = Secrets::hash($deviceCode);
        $authorization = $this->storage->findDeviceAuthorization($hash);
        if ($authorization === null || !hash_equals($authorization->clientId, $client->clientId())) {
            throw PoppyError::invalidGrant('The device code is unknown.');
        }

        $now = $this->clock->now();
        if ($authorization->isExpired($now)) {
            throw PoppyError::expiredToken();
        }

        switch ($authorization->status) {
            case DeviceStatus::Denied:
                throw PoppyError::accessDenied();
            case DeviceStatus::Consumed:
                throw PoppyError::invalidGrant('The device code was already used.');
            case DeviceStatus::Pending:
                $tooSoon = $authorization->lastPolledAt !== null
                    && $now->getTimestamp() - $authorization->lastPolledAt->getTimestamp() < $authorization->interval;
                $interval = $authorization->interval + ($tooSoon ? self::SLOW_DOWN_STEP : 0);
                $this->storage->saveDeviceAuthorization($authorization->polled($now, $interval));

                throw $tooSoon ? PoppyError::slowDown() : PoppyError::authorizationPending();
            case DeviceStatus::Approved:
                break;
        }

        $session = $this->activeSession($parameters['session_id'] ?? null);
        if (!hash_equals($session->clientId, $client->clientId())) {
            throw PoppyError::invalidSession();
        }

        $approved = $this->storage->consumeApprovedDeviceAuthorization($hash);
        if ($approved === null || $approved->accountId === null) {
            throw PoppyError::invalidGrant('The device code was already used.');
        }

        return $this->signIn($session, $approved->accountId, $approved->grantedScopes, $type, $jkt, $resource);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, mixed>
     */
    private function refreshToken(AuthenticatedClient $client, array $parameters, TokenType $type, ?string $jkt, ?string $resource): array
    {
        $value = $parameters['refresh_token'] ?? null;
        if (!is_string($value)) {
            throw PoppyError::invalidGrant('refresh_token is missing');
        }

        $token = $this->storage->findAccountTokenByHash(Secrets::hash($value));
        if ($token === null || !$token->isUsable($this->clock->now()) || !hash_equals($token->clientId, $client->clientId())) {
            throw PoppyError::invalidGrant('The Account Token is unknown, expired or revoked.');
        }

        $scopes = Scopes::parse($parameters['scope'] ?? null, $token->scopes, required: false);
        if ($scopes === []) {
            $scopes = $token->scopes;
        }

        $sessionId = $parameters['session_id'] ?? null;
        if ($sessionId === null) {
            $session = $this->issuer->startSession($client->clientId(), $token->userId);
        } else {
            $session = $this->activeSession($sessionId);
            if (!$session->belongsTo($client->clientId(), $token->userId)) {
                throw PoppyError::invalidSession();
            }
            if ($session->accountId !== null && !hash_equals($session->accountId, $token->accountId)) {
                throw PoppyError::accountMismatch();
            }
        }

        $session = $session->signIn($token, $scopes);
        $this->storage->saveSession($session);

        return $this->issuer->sessionTokenResponse($session, $type, $jkt, $resource, $scopes);
    }

    /**
     * Signs a Session in after Direct or Device Sign-In and returns the token
     * response with the new Account Token. A Session that was ever signed in
     * to another account cannot switch (4.4): that ends in account_mismatch
     * and no tokens at all.
     *
     * @param list<string> $scopes
     *
     * @return array<string, mixed>
     */
    private function signIn(Session $session, string $accountId, array $scopes, TokenType $type, ?string $jkt, ?string $resource): array
    {
        if ($session->accountId !== null && !hash_equals($session->accountId, $accountId)) {
            throw PoppyError::accountMismatch();
        }

        $issued = $this->issuer->accountToken($session, $accountId, $scopes);
        $session = $session->signIn($issued->token, $scopes);
        $this->storage->saveSession($session);

        return $this->issuer->sessionTokenResponse($session, $type, $jkt, $resource, $scopes, $issued);
    }

    private function activeSession(mixed $sessionId): Session
    {
        if (!is_string($sessionId) || $sessionId === '') {
            throw PoppyError::invalidRequest('session_id is required');
        }

        $session = $this->storage->findSession($sessionId);
        if ($session === null || !$session->isActive($this->clock->now())) {
            throw PoppyError::invalidSession();
        }

        return $session;
    }
}
