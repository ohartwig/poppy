<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\SignIn;

use Koh\Poppy\Client\ClientMetadataResolver;
use Koh\Poppy\Client\ClientPolicy;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Http\Url;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Pkce;
use Koh\Poppy\Server\Scopes;
use Koh\Poppy\Server\Secrets;
use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;

/**
 * Direct Sign-In: the authorization code flow with PKCE (Poppy 0.2, 4.5).
 *
 * The integration owns the pages — the User signs in however the shop or site
 * allows and then sees the consent page — and calls this class at the two
 * ends: validate() when the request arrives, approve() or deny() when the User
 * has decided. Opening the URL never approves anything by itself.
 */
final readonly class DirectSignIn
{
    public function __construct(
        private ServerConfiguration $configuration,
        private PoppyStorage $storage,
        private ClientMetadataResolver $resolver,
        private ClientPolicy $policy,
        private ClockInterface $clock,
    ) {}

    /**
     * @param array<string, mixed> $query the authorization request's query parameters
     *
     * @throws AuthorizationError
     */
    public function validate(array $query): AuthorizationRequest
    {
        if (!$this->configuration->hasDirectSignIn()) {
            throw AuthorizationError::shown('Direct Sign-In is not offered here.');
        }

        $clientId = $query['client_id'] ?? null;
        if (!is_string($clientId) || !Url::isHttps($clientId) || !$this->policy->accepts($clientId)) {
            throw AuthorizationError::shown('This Personal Agent is not accepted.');
        }

        try {
            $client = $this->resolver->resolve($clientId);
        } catch (InvalidClientMetadata) {
            throw AuthorizationError::shown('The Personal Agent\'s metadata could not be verified.');
        }

        $redirectUri = $query['redirect_uri'] ?? null;
        if (!is_string($redirectUri) || !$client->allowsRedirectUri($redirectUri)) {
            throw AuthorizationError::shown('The redirect URI is not registered for this Personal Agent.');
        }

        $state = $query['state'] ?? null;
        $state = is_string($state) && $state !== '' ? $state : null;

        if (($query['response_type'] ?? null) !== 'code') {
            throw $this->redirectedError($redirectUri, $state, 'unsupported_response_type', 'response_type must be code');
        }

        $challenge = $query['code_challenge'] ?? null;
        if (($query['code_challenge_method'] ?? null) !== 'S256' || !is_string($challenge) || !Pkce::isValidChallenge($challenge)) {
            throw $this->redirectedError($redirectUri, $state, 'invalid_request', 'PKCE with S256 is required');
        }

        try {
            $scopes = Scopes::parse($query['scope'] ?? null, $this->configuration->directScopes ?? []);
        } catch (PoppyError $error) {
            throw $this->redirectedError($redirectUri, $state, $error->error, $error->getMessage());
        }

        return new AuthorizationRequest($client, $redirectUri, $scopes, $challenge, $state);
    }

    /**
     * Rebuilds a request kept across the User's sign-in from toArray(). The
     * client is resolved again, so a Personal Agent blocked or changed in the
     * meantime does not get a code.
     *
     * @param array<mixed> $stored
     *
     * @throws AuthorizationError
     */
    public function restore(array $stored): AuthorizationRequest
    {
        $scopes = $stored['scope'] ?? null;
        return $this->validate([
            'client_id' => $stored['client_id'] ?? null,
            'redirect_uri' => $stored['redirect_uri'] ?? null,
            'state' => $stored['state'] ?? null,
            'response_type' => 'code',
            'code_challenge' => $stored['code_challenge'] ?? null,
            'code_challenge_method' => 'S256',
            'scope' => is_array($scopes) ? implode(' ', array_filter($scopes, 'is_string')) : null,
        ]);
    }

    /**
     * The User signed in and approved some or all of the requested scopes.
     *
     * @param list<string> $approvedScopes must be a non-empty subset of the request's scopes
     *
     * @return string the URL to redirect the browser to
     */
    public function approve(AuthorizationRequest $request, string $accountId, array $approvedScopes): string
    {
        $scopes = array_values(array_intersect($request->scopes, $approvedScopes));
        if ($scopes === []) {
            return $this->deny($request);
        }

        $code = Secrets::token('pac_');
        $this->storage->saveAuthorizationCode(new AuthorizationCode(
            Secrets::hash($code),
            $request->client->clientId,
            $request->redirectUri,
            $request->codeChallenge,
            $accountId,
            $scopes,
            $this->clock->now()->modify('+' . $this->configuration->authorizationCodeTtl . ' seconds'),
        ));

        return $this->redirect($request->redirectUri, ['code' => $code, 'state' => $request->state]);
    }

    public function deny(AuthorizationRequest $request): string
    {
        return $this->redirect($request->redirectUri, ['error' => 'access_denied', 'state' => $request->state]);
    }

    private function redirectedError(string $redirectUri, ?string $state, string $error, string $description): AuthorizationError
    {
        return AuthorizationError::redirected($error, $description, $this->redirect($redirectUri, [
            'error' => $error,
            'error_description' => $description,
            'state' => $state,
        ]));
    }

    /** @param array<string, string|null> $parameters */
    private function redirect(string $redirectUri, array $parameters): string
    {
        $parameters['iss'] = $this->configuration->issuer;
        $query = http_build_query(array_filter($parameters, static fn (?string $value): bool => $value !== null), '', '&', PHP_QUERY_RFC3986);

        return $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . $query;
    }
}
