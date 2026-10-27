<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Server\SignIn\AuthorizationError;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\TestCase;

/** Direct and Device Sign-In, Account Tokens and sign-out (Poppy 0.2, 4.4–4.9). */
final class SignInTest extends TestCase
{
    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->company = new TestCompany();
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testDirectSignInSignsTheSessionInAndIssuesAnAccountToken(): void
    {
        $session = $this->company->startSession($this->agent);
        [$code, $verifier] = $this->directSignIn(['poppy:read', 'poppy:write'], approve: ['poppy:read']);

        $body = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => TestCompany::text($session, 'session_id'),
        ]));

        self::assertTrue($body['signed_in']);
        self::assertSame('poppy:read', $body['scope'], 'the User approved fewer scopes than requested');
        self::assertSame($session['session_id'], $body['session_id']);
        self::assertIsString($body['refresh_token']);
        self::assertStringStartsWith('pat_', $body['refresh_token']);
        self::assertSame(7776000, $body['refresh_token_expires_in']);
    }

    public function testTheCodeCanBeExchangedOnce(): void
    {
        $session = $this->company->startSession($this->agent);
        [$code, $verifier] = $this->directSignIn(['poppy:read']);
        $exchange = fn () => $this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => TestCompany::text($session, 'session_id'),
        ]);

        self::assertSame(200, $exchange()->getStatusCode());
        self::assertSame('invalid_grant', TestCompany::json($exchange())['error']);
    }

    public function testAWrongVerifierFails(): void
    {
        $session = $this->company->startSession($this->agent);
        [$code] = $this->directSignIn(['poppy:read']);

        $response = $this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => str_repeat('a', 43),
            'session_id' => TestCompany::text($session, 'session_id'),
        ]);

        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testASessionCannotSwitchAccounts(): void
    {
        $session = $this->company->startSession($this->agent);
        $this->signInDirect(TestCompany::text($session, 'session_id'), 'account-A');

        [$code, $verifier] = $this->directSignIn(['poppy:read'], account: 'account-B');
        $response = $this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => TestCompany::text($session, 'session_id'),
        ]);

        self::assertSame('account_mismatch', TestCompany::json($response)['error']);
        self::assertArrayNotHasKey('refresh_token', TestCompany::json($response));
    }

    public function testTheAccountTokenStartsASignedInSessionAndCanNarrowScopes(): void
    {
        $session = $this->company->startSession($this->agent);
        $accountToken = $this->signInDirect(TestCompany::text($session, 'session_id'), 'account-A', ['poppy:read', 'poppy:write']);

        $body = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $accountToken,
            'scope' => 'poppy:read',
        ]));

        self::assertTrue($body['signed_in']);
        self::assertSame('poppy:read', $body['scope']);
        self::assertNotSame($session['session_id'], $body['session_id']);
        self::assertArrayNotHasKey('refresh_token', $body);

        $wider = $this->company->token($this->agent, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $accountToken,
            'scope' => 'addresses',
        ]);
        self::assertSame('invalid_scope', TestCompany::json($wider)['error']);
    }

    public function testAnAccountTokenIsUselessToAnotherAgent(): void
    {
        $session = $this->company->startSession($this->agent);
        $accountToken = $this->signInDirect(TestCompany::text($session, 'session_id'), 'account-A');

        $thief = new PersonalAgent('https://thief.example/agent.json', 'https://thief.example/jwks.json', 'https://thief.example/cb');
        $thief->publish($this->company->http);

        $response = $this->company->token($thief, ['grant_type' => 'refresh_token', 'refresh_token' => $accountToken]);

        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testSigningOutRevokesTheAccountTokenAndSignsSessionsOut(): void
    {
        $session = $this->company->startSession($this->agent);
        $accountToken = $this->signInDirect(TestCompany::text($session, 'session_id'), 'account-A');

        $now = $this->company->clock->now();
        $revocation = $this->company->server->revocationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->revocation,
            ['token' => $accountToken, 'token_type_hint' => 'refresh_token'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $now),
        ));
        self::assertSame(200, $revocation->getStatusCode());

        $stored = $this->company->storage->findSession(TestCompany::text($session, 'session_id'));
        self::assertNotNull($stored);
        self::assertFalse($stored->isSignedIn());
        self::assertSame('account-A', $stored->accountId, 'the Session stays bound to its account');

        $refused = $this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountToken]);
        self::assertSame('invalid_grant', TestCompany::json($refused)['error']);

        // The Session continues signed out and renews with the assertion.
        $renewed = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_Q7c1vK', $now),
            'session_id' => TestCompany::text($session, 'session_id'),
        ]);
        self::assertFalse(TestCompany::json($renewed)['signed_in']);
    }

    public function testRevokingAnUnknownTokenAnswers200(): void
    {
        $response = $this->company->server->revocationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->revocation,
            ['token' => 'pat_unknown'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        ));

        self::assertSame(200, $response->getStatusCode());
    }

    public function testDeviceSignIn(): void
    {
        $session = $this->company->startSession($this->agent);
        $now = $this->company->clock->now();

        $start = $this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $now),
        ));
        self::assertSame(200, $start->getStatusCode(), (string) $start->getBody());
        $device = TestCompany::json($start);
        self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', TestCompany::text($device, 'user_code'));
        self::assertStringStartsWith('https://shop.example/poppy/device?user_code=', TestCompany::text($device, 'verification_uri_complete'));

        $poll = fn () => TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_DEVICE_CODE,
            'device_code' => TestCompany::text($device, 'device_code'),
            'session_id' => TestCompany::text($session, 'session_id'),
        ]));

        self::assertSame('authorization_pending', $poll()['error']);
        self::assertSame('slow_down', $poll()['error'], 'polled again without waiting the interval');

        $this->company->clock->advance(11);
        $verification = $this->company->server->deviceVerification();
        $found = $verification->find(strtolower(str_replace('-', ' ', TestCompany::text($device, 'user_code'))));
        self::assertNotNull($found, 'the code is found however the User types it');
        [$authorization, $client] = $found;
        self::assertSame('Example Agent', $client->displayName());

        $verification->approve($authorization, 'account-A', ['poppy:read']);

        $tokens = $poll();
        self::assertTrue($tokens['signed_in']);
        self::assertSame('poppy:read', $tokens['scope']);
        self::assertArrayHasKey('refresh_token', $tokens);

        self::assertSame('invalid_grant', $poll()['error'], 'a device code is exchanged once');
    }

    public function testDeviceSignInDeclined(): void
    {
        $session = $this->company->startSession($this->agent);
        $device = TestCompany::json($this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        )));

        $found = $this->company->server->deviceVerification()->find(TestCompany::text($device, 'user_code'));
        self::assertNotNull($found);
        $this->company->server->deviceVerification()->deny($found[0]);

        $response = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_DEVICE_CODE,
            'device_code' => TestCompany::text($device, 'device_code'),
            'session_id' => TestCompany::text($session, 'session_id'),
        ]));
        self::assertSame('access_denied', $response['error']);
    }

    public function testDeviceScopesAreLimitedToTheDeviceType(): void
    {
        $response = $this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:write'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        ));

        self::assertSame('invalid_scope', TestCompany::json($response)['error']);
    }

    public function testAnUnregisteredRedirectUriIsShownNotRedirected(): void
    {
        try {
            $this->company->server->directSignIn()->validate($this->authorizationQuery(['poppy:read'], 'x', ['redirect_uri' => 'https://agent.example/elsewhere']));
            self::fail('expected an error');
        } catch (AuthorizationError $error) {
            self::assertFalse($error->isRedirect());
        }
    }

    public function testErrorsAfterTheRedirectUriIsVerifiedGoBackWithIss(): void
    {
        try {
            $this->company->server->directSignIn()->validate($this->authorizationQuery(['poppy:read'], 'x', ['code_challenge_method' => 'plain']));
            self::fail('expected an error');
        } catch (AuthorizationError $error) {
            self::assertTrue($error->isRedirect());
            self::assertStringContainsString('iss=' . rawurlencode(TestCompany::ISSUER), (string) $error->redirectUrl);
            self::assertStringContainsString('state=st', (string) $error->redirectUrl);
        }
    }

    public function testARestoredRequestIsValidatedAgain(): void
    {
        $signIn = $this->company->server->directSignIn();
        $request = $signIn->validate($this->authorizationQuery(['poppy:read'], 'x'));

        $restored = $signIn->restore($request->toArray());

        self::assertSame($request->toArray(), $restored->toArray());
    }

    /**
     * @param list<string> $scopes
     * @param list<string>|null $approve
     *
     * @return array{string, string} code and verifier
     */
    private function directSignIn(array $scopes, ?array $approve = null, string $account = 'account-A'): array
    {
        $verifier = Base64Url::encode(random_bytes(32));
        $signIn = $this->company->server->directSignIn();
        $request = $signIn->validate($this->authorizationQuery($scopes, $verifier));
        $redirect = $signIn->approve($request, $account, $approve ?? $scopes);

        self::assertStringStartsWith($this->agent->redirectUri . '?', $redirect);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        self::assertSame(TestCompany::ISSUER, $query['iss'] ?? null, 'RFC 9207 iss in the redirect');
        self::assertSame('st', $query['state'] ?? null);
        self::assertIsString($query['code'] ?? null);

        return [$query['code'], $verifier];
    }

    /** @param list<string> $scopes @return string the Account Token */
    private function signInDirect(string $sessionId, string $account, array $scopes = ['poppy:read']): string
    {
        [$code, $verifier] = $this->directSignIn($scopes, account: $account);
        $body = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => $sessionId,
        ]));
        self::assertIsString($body['refresh_token'] ?? null);

        return $body['refresh_token'];
    }

    /**
     * @param list<string>          $scopes
     * @param array<string, string> $overrides
     *
     * @return array<string, string>
     */
    private function authorizationQuery(array $scopes, string $verifier, array $overrides = []): array
    {
        return $overrides + [
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => implode(' ', $scopes),
            'state' => 'st',
            'code_challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ];
    }
}
