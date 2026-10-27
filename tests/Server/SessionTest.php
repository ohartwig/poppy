<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\TestCase;

/** Starting and renewing signed-out Sessions (Poppy 0.2, 4.1–4.3). */
final class SessionTest extends TestCase
{
    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->company = new TestCompany();
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testStartsASignedOutSessionWithADpopBoundToken(): void
    {
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        $body = TestCompany::json($response);
        self::assertSame('DPoP', $body['token_type']);
        self::assertSame(3600, $body['expires_in']);
        self::assertSame('', $body['scope']);
        self::assertFalse($body['signed_in']);
        self::assertIsString($body['session_id']);
        self::assertStringStartsWith('ses_', $body['session_id']);
        self::assertArrayNotHasKey('refresh_token', $body);

        $session = $this->company->storage->findSession($body['session_id']);
        self::assertNotNull($session);
        self::assertSame('usr_1', $session->userId);
        self::assertSame($this->agent->clientId, $session->clientId);
    }

    public function testRenewsTheSameSession(): void
    {
        $first = $this->company->startSession($this->agent, 'usr_1');
        $this->company->clock->advance(3700);

        $renewed = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'session_id' => TestCompany::text($first, 'session_id'),
        ]));

        self::assertSame($first['session_id'], $renewed['session_id']);
        self::assertNotSame($first['access_token'], $renewed['access_token']);
    }

    public function testRenewingAnotherUsersSessionIsInvalidSession(): void
    {
        $first = $this->company->startSession($this->agent, 'usr_1');

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_2', $this->company->clock->now()),
            'session_id' => TestCompany::text($first, 'session_id'),
        ]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_session', TestCompany::json($response)['error']);
    }

    public function testAnEndedSessionIsInvalidSession(): void
    {
        $first = $this->company->startSession($this->agent, 'usr_1');
        $this->company->clock->advance($this->company->configuration->sessionLifetime + 1);

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'session_id' => TestCompany::text($first, 'session_id'),
        ]);

        self::assertSame('invalid_session', TestCompany::json($response)['error']);
    }

    public function testAReplayedSessionAssertionIsRefused(): void
    {
        $assertion = $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now());
        $parameters = ['grant_type' => TokenEndpoint::GRANT_JWT_BEARER, 'assertion' => $assertion];

        self::assertSame(200, $this->company->token($this->agent, $parameters)->getStatusCode());

        $replay = $this->company->token($this->agent, $parameters);
        self::assertSame(400, $replay->getStatusCode());
        self::assertSame('invalid_grant', TestCompany::json($replay)['error']);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function badSessionAssertions(): iterable
    {
        yield 'aud as array' => [['aud' => [TestCompany::ISSUER]]];
        yield 'aud is the token endpoint' => [['aud' => TestCompany::ISSUER . '/token']];
        yield 'lives longer than five minutes' => [['exp' => 1_793_102_400 + 301, 'iat' => 1_793_102_400]];
        yield 'short jti' => [['jti' => 'abc']];
        yield 'other issuer' => [['iss' => 'https://other.example/agent.json']];
    }

    /** @param array<string, mixed> $overrides */
    #[\PHPUnit\Framework\Attributes\DataProvider('badSessionAssertions')]
    public function testRefusesBrokenSessionAssertions(array $overrides): void
    {
        if (is_int($overrides['iat'] ?? null)) {
            $this->company->clock->advance($overrides['iat'] - $this->company->clock->now()->getTimestamp());
        }

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now(), $overrides),
        ]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', TestCompany::json($response)['error']);
    }

    public function testClientAssertionAudienceMustBeTheIssuer(): void
    {
        $now = $this->company->clock->now();
        $endpoint = $this->company->configuration->endpoints->token;
        $response = $this->company->server->tokenEndpoint()->handle(TestCompany::form($endpoint, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $now),
        ] + $this->agent->clientAuthentication(TestCompany::ISSUER, $now, ['aud' => $endpoint]), $this->agent->dpopProof('POST', $endpoint, $now)));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', TestCompany::json($response)['error']);
    }

    public function testAReplayedClientAssertionIsRefused(): void
    {
        $now = $this->company->clock->now();
        $endpoint = $this->company->configuration->endpoints->token;
        $authentication = $this->agent->clientAuthentication(TestCompany::ISSUER, $now);
        $send = fn () => $this->company->server->tokenEndpoint()->handle(TestCompany::form($endpoint, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $now),
        ] + $authentication, $this->agent->dpopProof('POST', $endpoint, $now)));

        self::assertSame(200, $send()->getStatusCode());
        self::assertSame('invalid_client', TestCompany::json($send())['error']);
    }

    public function testABlockedAgentIsRefusedWithoutAnyFetch(): void
    {
        $company = new TestCompany(blocked: ['agent.example']);
        $this->agent->publish($company->http);

        $response = $company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $company->clock->now()),
        ]);

        self::assertSame('invalid_client', TestCompany::json($response)['error']);
        self::assertSame([], $company->http->requested);
    }

    public function testMetadataThatDoesNotNameItsOwnUrlIsRefused(): void
    {
        $this->agent->publish($this->company->http, ['client_id' => 'https://agent.example/other.json']);

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
        ]);

        self::assertSame('invalid_client', TestCompany::json($response)['error']);
    }

    public function testAKeySetOnAnotherDomainIsRefused(): void
    {
        $this->agent->publish($this->company->http, ['jwks_uri' => 'https://evil.example/jwks.json']);

        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
        ]);

        self::assertSame('invalid_client', TestCompany::json($response)['error']);
    }

    public function testATokenRequestWithoutDpopIsRefused(): void
    {
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
        ], dpop: false);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_dpop_proof', TestCompany::json($response)['error']);
    }

    public function testAnMcpServerWithoutDpopGetsABearerTokenWithoutAProof(): void
    {
        $body = $this->company->startSession($this->agent, 'usr_1');
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'session_id' => TestCompany::text($body, 'session_id'),
            'resource' => TestCompany::MCP,
        ], dpop: false);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('Bearer', TestCompany::json($response)['token_type']);
    }

    public function testAnMcpServerWithDpopNeverGetsABearerToken(): void
    {
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'resource' => TestCompany::DPOP_MCP,
        ], dpop: false);

        self::assertSame('invalid_dpop_proof', TestCompany::json($response)['error']);
    }

    public function testAnUnknownResourceIsInvalidTarget(): void
    {
        $response = $this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'resource' => 'https://other.example/mcp',
        ]);

        self::assertSame('invalid_target', TestCompany::json($response)['error']);
    }

    public function testARepeatedParameterIsRefused(): void
    {
        $now = $this->company->clock->now();
        $endpoint = $this->company->configuration->endpoints->token;
        $request = TestCompany::form($endpoint, $this->agent->clientAuthentication(TestCompany::ISSUER, $now), $this->agent->dpopProof('POST', $endpoint, $now));
        $request->getBody()->seek(0, SEEK_END);
        $request->getBody()->write('&grant_type=refresh_token&grant_type=' . rawurlencode(TokenEndpoint::GRANT_JWT_BEARER));

        $response = $this->company->server->tokenEndpoint()->handle($request);

        self::assertSame('invalid_request', TestCompany::json($response)['error']);
    }
}
