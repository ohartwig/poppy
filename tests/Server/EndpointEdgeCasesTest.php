<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Server\Endpoints;
use Koh\Poppy\Server\RateLimiter;
use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Server\SignIn\AuthorizationError;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class EndpointEdgeCasesTest extends TestCase
{
    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->company = new TestCompany();
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testOnlyPostIsAccepted(): void
    {
        $get = new ServerRequest('GET', $this->company->configuration->endpoints->token);

        foreach ([
            $this->company->server->tokenEndpoint()->handle($get),
            $this->company->server->revocationEndpoint()->handle($get),
            $this->company->server->deviceAuthorizationEndpoint()->handle($get),
        ] as $response) {
            self::assertSame(400, $response->getStatusCode());
            self::assertSame('invalid_request', TestCompany::json($response)['error']);
        }
    }

    public function testAnUnknownGrantType(): void
    {
        self::assertSame('unsupported_grant_type', TestCompany::json($this->company->token($this->agent, ['grant_type' => 'password']))['error']);
        self::assertSame('unsupported_grant_type', TestCompany::json($this->company->token($this->agent, []))['error']);
    }

    public function testMissingGrantParameters(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent), 'session_id');
        foreach ([
            [['grant_type' => TokenEndpoint::GRANT_JWT_BEARER], 'invalid_grant'],
            [['grant_type' => 'authorization_code', 'session_id' => $session], 'invalid_grant'],
            [['grant_type' => 'authorization_code', 'code' => 'x', 'session_id' => $session], 'invalid_request'],
            [['grant_type' => 'authorization_code', 'code' => 'x', 'redirect_uri' => 'https://agent.example/cb', 'code_verifier' => str_repeat('a', 43)], 'invalid_request'],
            [['grant_type' => 'authorization_code', 'code' => 'x', 'redirect_uri' => 'https://agent.example/cb', 'code_verifier' => str_repeat('a', 43), 'session_id' => 'ses_unknown'], 'invalid_session'],
            [['grant_type' => TokenEndpoint::GRANT_DEVICE_CODE], 'invalid_grant'],
            [['grant_type' => TokenEndpoint::GRANT_DEVICE_CODE, 'device_code' => 'pdc_unknown'], 'invalid_grant'],
            [['grant_type' => 'refresh_token'], 'invalid_grant'],
            [['grant_type' => 'refresh_token', 'refresh_token' => 'pat_unknown'], 'invalid_grant'],
        ] as [$parameters, $error]) {
            self::assertSame($error, TestCompany::json($this->company->token($this->agent, $parameters))['error'], json_encode($parameters, JSON_THROW_ON_ERROR));
        }
    }

    public function testASignedOutTokenCarriesNoScope(): void
    {
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'scope' => 'poppy:read',
        ]);

        self::assertSame('invalid_scope', TestCompany::json($response)['error']);
    }

    public function testASignedInSessionIsNotRenewedWithTheAssertion(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $this->signIn($session, 'account-A');

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'session_id' => $session,
        ]);

        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testAnAccountTokenCanSignInAnExistingSessionOfTheSameAccountOnly(): void
    {
        $first = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $accountA = $this->signIn($first, 'account-A');

        $second = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $signedIn = TestCompany::json($this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountA, 'session_id' => $second]));
        self::assertTrue($signedIn['signed_in']);
        self::assertSame($second, $signedIn['session_id']);

        $third = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $accountB = $this->signIn($third, 'account-B');
        $mismatch = $this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountB, 'session_id' => $second]);
        self::assertSame('account_mismatch', TestCompany::json($mismatch)['error']);

        $otherUser = TestCompany::text($this->company->startSession($this->agent, 'usr_2'), 'session_id');
        $wrongUser = $this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountA, 'session_id' => $otherUser]);
        self::assertSame('invalid_session', TestCompany::json($wrongUser)['error']);
    }

    public function testAnExpiredAccountTokenIsInvalidGrant(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $accountToken = $this->signIn($session, 'account-A');
        $this->company->clock->advance(7776000);

        self::assertSame('invalid_grant', TestCompany::json($this->company->token($this->agent, ['grant_type' => 'refresh_token', 'refresh_token' => $accountToken]))['error']);
    }

    public function testCodesExpireAndAreBoundToTheirRedirectUri(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');

        [$code, $verifier] = $this->code();
        $this->company->clock->advance(120);
        $expired = $this->company->token($this->agent, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->agent->redirectUri, 'code_verifier' => $verifier, 'session_id' => $session]);
        self::assertSame('invalid_grant', TestCompany::json($expired)['error']);

        [$code, $verifier] = $this->code();
        $this->company->clock->advance(119);
        $elsewhere = $this->company->token($this->agent, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->agent->redirectUri . '/x', 'code_verifier' => $verifier, 'session_id' => $session]);
        self::assertSame('invalid_grant', TestCompany::json($elsewhere)['error']);
    }

    public function testACodeIsUselessToAnotherAgent(): void
    {
        $thief = new PersonalAgent('https://thief.example/agent.json', 'https://thief.example/jwks.json', 'https://agent.example/oauth/callback');
        $thief->publish($this->company->http, ['redirect_uris' => []]);
        $session = TestCompany::text($this->company->startSession($thief, 'usr_1'), 'session_id');
        [$code, $verifier] = $this->code();

        $response = $this->company->token($thief, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->agent->redirectUri, 'code_verifier' => $verifier, 'session_id' => $session]);

        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testACodeForAnotherAgentsSessionIsInvalidSession(): void
    {
        $other = new PersonalAgent('https://other.example/agent.json', 'https://other.example/jwks.json', 'https://other.example/cb');
        $other->publish($this->company->http);
        $foreignSession = TestCompany::text($this->company->startSession($other, 'usr_1'), 'session_id');
        [$code, $verifier] = $this->code();

        $response = $this->company->token($this->agent, ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => $this->agent->redirectUri, 'code_verifier' => $verifier, 'session_id' => $foreignSession]);

        self::assertSame('invalid_session', TestCompany::json($response)['error']);
    }

    public function testDevicePollingIntervalAndExpiry(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $device = $this->device();
        $poll = fn (): string => TestCompany::text(TestCompany::json($this->company->token($this->agent, ['grant_type' => TokenEndpoint::GRANT_DEVICE_CODE, 'device_code' => $device, 'session_id' => $session])) + ['error' => 'tokens'], 'error');

        self::assertSame('authorization_pending', $poll());
        $this->company->clock->advance(4);
        self::assertSame('slow_down', $poll(), 'four seconds is under the five-second interval');
        $this->company->clock->advance(9);
        self::assertSame('slow_down', $poll(), 'the interval grew to ten seconds');
        $this->company->clock->advance(15);
        self::assertSame('authorization_pending', $poll(), 'fifteen seconds is enough');

        $this->company->clock->advance(600);
        self::assertSame('expired_token', $poll());
    }

    public function testADeviceCodeOfAnotherAgentIsInvalidGrant(): void
    {
        $device = $this->device();
        $other = new PersonalAgent('https://other.example/agent.json', 'https://other.example/jwks.json', 'https://other.example/cb');
        $other->publish($this->company->http);
        $session = TestCompany::text($this->company->startSession($other, 'usr_1'), 'session_id');

        $response = $this->company->token($other, ['grant_type' => TokenEndpoint::GRANT_DEVICE_CODE, 'device_code' => $device, 'session_id' => $session]);

        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testDeviceSignInIntoAnotherAccountIsAccountMismatchAndConsumesTheCode(): void
    {
        $session = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'session_id');
        $this->signIn($session, 'account-A');
        $device = $this->device();
        $found = $this->company->server->deviceVerification()->find($this->userCodeOf($device));
        self::assertNotNull($found);
        $this->company->server->deviceVerification()->approve($found[0], 'account-B', ['poppy:read']);

        $poll = fn (): array => TestCompany::json($this->company->token($this->agent, ['grant_type' => TokenEndpoint::GRANT_DEVICE_CODE, 'device_code' => $device, 'session_id' => $session]));
        self::assertSame('account_mismatch', $poll()['error']);
        self::assertSame('invalid_grant', $poll()['error']);
    }

    public function testApprovingNoScopeDeclines(): void
    {
        $device = $this->device();
        $verification = $this->company->server->deviceVerification();
        $found = $verification->find($this->userCodeOf($device));
        self::assertNotNull($found);
        $verification->approve($found[0], 'account-A', ['poppy:write']);

        self::assertNull($verification->find($this->userCodeOf($device)), 'no longer pending');
        $stored = $this->company->storage->findDeviceAuthorization(hash('sha256', $device));
        self::assertSame('denied', $stored?->status->value);
        self::assertNull($verification->find('nonsense'));
    }

    public function testAnExpiredUserCodeIsNotFound(): void
    {
        $device = $this->device();
        $this->company->clock->advance(600);

        self::assertNull($this->company->server->deviceVerification()->find($this->userCodeOf($device)));
    }

    public function testDeviceSignInIsOffWithoutDeviceScopes(): void
    {
        $company = $this->companyWith(new ServerConfiguration(TestCompany::ISSUER, ['shop.example'], Endpoints::below(TestCompany::ISSUER)));
        $this->agent->publish($company->http);

        $response = $company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(TestCompany::ISSUER . '/device_authorization', ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $company->clock->now())));

        self::assertSame('unsupported_grant_type', TestCompany::json($response)['error']);
        $this->expectException(AuthorizationError::class);
        $company->server->directSignIn()->validate(['client_id' => $this->agent->clientId]);
    }

    public function testRateLimitsAnswer429WithRetryAfter(): void
    {
        $limiter = new class implements RateLimiter {
            /** @var list<string> */
            public array $hits = [];

            public function hit(string $bucket, string $key): int
            {
                $this->hits[] = $bucket . ':' . $key;

                return 30;
            }
        };
        $company = $this->companyWith(null, $limiter);
        $this->agent->publish($company->http);
        $now = $company->clock->now();

        $token = $company->server->tokenEndpoint()->handle(TestCompany::form(TestCompany::ISSUER . '/token', $this->agent->clientAuthentication(TestCompany::ISSUER, $now)));
        $revoke = $company->server->revocationEndpoint()->handle(TestCompany::form(TestCompany::ISSUER . '/revoke', ['token' => 'x'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $now)));
        $device = $company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(TestCompany::ISSUER . '/device_authorization', ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $now)));

        foreach ([$token, $revoke, $device] as $response) {
            self::assertSame(429, $response->getStatusCode());
            self::assertSame('30', $response->getHeaderLine('Retry-After'));
            self::assertSame('rate_limited', TestCompany::json($response)['error']);
        }
        self::assertSame(['token:' . $this->agent->clientId, 'revoke:' . $this->agent->clientId, 'device:' . $this->agent->clientId], $limiter->hits);
        self::assertSame([], $company->http->requested, 'nothing is fetched for a limited request');
    }

    public function testASuccessfulResponseCarriesTheNextNonce(): void
    {
        $company = $this->companyWith(null, null, true);
        $this->agent->publish($company->http);
        $now = $company->clock->now();
        $endpoint = TestCompany::ISSUER . '/token';
        $parameters = ['grant_type' => TokenEndpoint::GRANT_JWT_BEARER, 'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $now)];

        $first = $company->server->tokenEndpoint()->handle(TestCompany::form($endpoint, $parameters + $this->agent->clientAuthentication(TestCompany::ISSUER, $now), $this->agent->dpopProof('POST', $endpoint, $now)));
        self::assertSame('use_dpop_nonce', TestCompany::json($first)['error']);
        $nonce = $first->getHeaderLine('DPoP-Nonce');
        self::assertNotSame('', $nonce);

        $parameters['assertion'] = $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $now);
        $second = $company->server->tokenEndpoint()->handle(TestCompany::form($endpoint, $parameters + $this->agent->clientAuthentication(TestCompany::ISSUER, $now), $this->agent->dpopProof('POST', $endpoint, $now, null, ['nonce' => $nonce])));
        self::assertSame(200, $second->getStatusCode(), (string) $second->getBody());
        self::assertSame($nonce, $second->getHeaderLine('DPoP-Nonce'));
    }

    public function testAuthorizationRequestValidation(): void
    {
        $signIn = $this->company->server->directSignIn();
        $valid = [
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read',
            'code_challenge' => Base64Url::encode(hash('sha256', str_repeat('v', 43), true)),
            'code_challenge_method' => 'S256',
        ];

        $request = $signIn->validate($valid);
        self::assertNull($request->state, 'no state is fine');
        self::assertSame(['poppy:read'], $request->scopes);

        foreach ([
            [['client_id' => 'http://agent.example/agent.json'], false],
            [['client_id' => 'https://unknown.example/agent.json'], false],
            [['client_id' => 5], false],
            [['redirect_uri' => null], false],
            [['response_type' => 'token'], true],
            [['code_challenge' => 'short'], true],
            [['code_challenge' => null], true],
            [['scope' => 'poppy:admin'], true],
            [['scope' => ''], true],
        ] as [$override, $redirects]) {
            try {
                $signIn->validate($override + $valid);
                self::fail(json_encode($override, JSON_THROW_ON_ERROR) . ' should be refused');
            } catch (AuthorizationError $error) {
                self::assertSame($redirects, $error->isRedirect(), json_encode($override, JSON_THROW_ON_ERROR));
            }
        }
    }

    public function testDenyRedirectsWithAccessDenied(): void
    {
        $signIn = $this->company->server->directSignIn();
        $request = $signIn->validate([
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read',
            'state' => 'a b',
            'code_challenge' => Base64Url::encode(hash('sha256', str_repeat('v', 43), true)),
            'code_challenge_method' => 'S256',
        ]);

        self::assertSame($this->agent->redirectUri . '?error=access_denied&state=a%20b&iss=' . rawurlencode(TestCompany::ISSUER), $signIn->deny($request));
        self::assertSame($signIn->deny($request), $signIn->approve($request, 'account-A', ['poppy:write']), 'approving nothing requested is declining');
    }

    /** @return array{string, string} */
    private function code(string $account = 'account-A'): array
    {
        $verifier = Base64Url::encode(random_bytes(32));
        $signIn = $this->company->server->directSignIn();
        $redirect = $signIn->approve($signIn->validate([
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read',
            'code_challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]), $account, ['poppy:read']);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        \assert(is_string($query['code'] ?? null));

        return [$query['code'], $verifier];
    }

    private function signIn(string $session, string $account): string
    {
        [$code, $verifier] = $this->code($account);

        return TestCompany::text(TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => $session,
        ])), 'refresh_token');
    }

    private function device(): string
    {
        return TestCompany::text(TestCompany::json($this->company->server->deviceAuthorizationEndpoint()->handle(TestCompany::form(
            $this->company->configuration->endpoints->deviceAuthorization,
            ['scope' => 'poppy:read'] + $this->agent->clientAuthentication(TestCompany::ISSUER, $this->company->clock->now()),
        ))), 'device_code');
    }

    private function userCodeOf(string $deviceCode): string
    {
        $stored = $this->company->storage->findDeviceAuthorization(hash('sha256', $deviceCode));
        \assert($stored !== null);

        return $stored->userCode;
    }

    private function companyWith(?ServerConfiguration $configuration, ?RateLimiter $limiter = null, bool $nonces = false): TestCompany
    {
        return new TestCompany(configuration: $configuration, rateLimiter: $limiter, nonces: $nonces);
    }
}
