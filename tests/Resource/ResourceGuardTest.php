<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Resource;

use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Resource\Challenge;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Tests\Support\KeyPair;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Koh\Poppy\Tests\Support\TestCompany;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/** Session Tokens at APIs and MCP servers (Poppy 0.2, 4.3 and section 6). */
final class ResourceGuardTest extends TestCase
{
    private const API = 'https://shop.example/api/orders';

    private TestCompany $company;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->company = new TestCompany();
        $this->agent = new PersonalAgent();
        $this->agent->publish($this->company->http);
    }

    public function testAcceptsADpopTokenWithAMatchingProof(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent, 'usr_1'), 'access_token');

        $context = $this->company->server->resourceGuard()->authenticate($this->apiRequest($token), self::API);

        self::assertSame('usr_1', $context->userId);
        self::assertSame($this->agent->clientId, $context->clientId);
        self::assertFalse($context->isSignedIn());
    }

    public function testRefusesAProofFromAnotherKey(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent), 'access_token');
        $request = $this->apiRequest($token, key: KeyPair::ec());

        $error = $this->refused($request);
        self::assertSame('invalid_dpop_proof', $error->error);
        self::assertSame(401, $error->status);
    }

    public function testRefusesAProofForAnotherToken(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent), 'access_token');
        $request = $this->apiRequest($token, ath: Base64Url::encode(hash('sha256', 'other', true)));

        self::assertSame('invalid_dpop_proof', $this->refused($request)->error);
    }

    public function testRefusesADpopTokenSentAsBearer(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent), 'access_token');
        $request = $this->apiRequest($token)->withHeader('Authorization', 'Bearer ' . $token);

        self::assertSame('invalid_token', $this->refused($request)->error);
    }

    public function testRefusesATokenInTheQueryString(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent), 'access_token');
        $request = (new ServerRequest('GET', self::API . '?access_token=' . $token))->withQueryParams(['access_token' => $token]);

        self::assertSame('invalid_token', $this->refused($request)->error);
    }

    public function testABearerTokenWorksOnlyAtItsMcpServer(): void
    {
        $session = $this->company->startSession($this->agent, 'usr_1');
        $bearer = TestCompany::text(TestCompany::json($this->company->token($this->agent, [
            'grant_type' => TokenEndpoint::GRANT_JWT_BEARER,
            'assertion' => $this->agent->sessionAssertion(TestCompany::ISSUER, 'usr_1', $this->company->clock->now()),
            'session_id' => TestCompany::text($session, 'session_id'),
            'resource' => TestCompany::MCP,
        ], dpop: false)), 'access_token');

        $guard = $this->company->server->resourceGuard();
        $atMcp = (new ServerRequest('POST', TestCompany::MCP))->withHeader('Authorization', 'Bearer ' . $bearer);
        self::assertSame('usr_1', $guard->authenticate($atMcp, TestCompany::MCP, TestCompany::MCP, mcp: true)->userId);

        $elsewhere = (new ServerRequest('POST', TestCompany::MCP . '/other'))->withHeader('Authorization', 'Bearer ' . $bearer);
        $this->expectException(PoppyError::class);
        $guard->authenticate($elsewhere, TestCompany::MCP . '/other', TestCompany::MCP . '/other', mcp: true);
    }

    public function testATokenWithoutResourceIsRefusedAtAnMcpServer(): void
    {
        $token = TestCompany::text($this->company->startSession($this->agent), 'access_token');
        $request = $this->apiRequest($token, url: TestCompany::DPOP_MCP);

        $this->expectException(PoppyError::class);
        $this->company->server->resourceGuard()->authenticate($request, TestCompany::DPOP_MCP, TestCompany::DPOP_MCP, mcp: true);
    }

    public function testSignOutTakesEffectOnTheNextRequest(): void
    {
        $session = $this->company->startSession($this->agent, 'usr_1');
        $verifier = Base64Url::encode(random_bytes(32));
        $signIn = $this->company->server->directSignIn();
        $redirect = $signIn->approve($signIn->validate([
            'response_type' => 'code',
            'client_id' => $this->agent->clientId,
            'redirect_uri' => $this->agent->redirectUri,
            'scope' => 'poppy:read',
            'code_challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
        ]), 'account-A', ['poppy:read']);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);

        $signedIn = TestCompany::json($this->company->token($this->agent, [
            'grant_type' => 'authorization_code',
            'code' => is_string($query['code'] ?? null) ? $query['code'] : '',
            'redirect_uri' => $this->agent->redirectUri,
            'code_verifier' => $verifier,
            'session_id' => TestCompany::text($session, 'session_id'),
        ]));
        $token = TestCompany::text($signedIn, 'access_token');

        $guard = $this->company->server->resourceGuard();
        $context = $guard->authenticate($this->apiRequest($token), self::API);
        self::assertSame('account-A', $context->requireScopes('poppy:read'));

        $accountToken = $this->company->storage->findAccountTokenByHash(hash('sha256', TestCompany::text($signedIn, 'refresh_token')));
        self::assertNotNull($accountToken);
        $this->company->server->disconnector()->revoke($accountToken);

        $after = $guard->authenticate($this->apiRequest($token), self::API);
        self::assertFalse($after->isSignedIn(), 'the same token is now handled as signed out');

        try {
            $after->requireScopes('poppy:read');
            self::fail('expected sign_in_required');
        } catch (PoppyError $error) {
            self::assertSame('sign_in_required', $error->error);
            self::assertSame(403, $error->status);
        }
    }

    public function testInsufficientScopeNamesTheScopes(): void
    {
        $error = PoppyError::insufficientScope(['poppy:read', 'poppy:write']);

        self::assertSame(
            'DPoP error="insufficient_scope", error_description="The token lacks required scopes.", scope="poppy:read poppy:write", algs="ES256"',
            Challenge::header($error, ['ES256']),
        );
    }

    public function testMcpChallengesNameBothSchemesAndTheMetadata(): void
    {
        $header = Challenge::header(PoppyError::invalidToken(), ['ES256'], dpop: true, bearer: true, resourceMetadata: 'https://shop.example/.well-known/oauth-protected-resource/mcp');

        self::assertStringStartsWith('DPoP error="invalid_token"', $header);
        self::assertStringContainsString(', Bearer error="invalid_token"', $header);
        self::assertSame(2, substr_count($header, 'resource_metadata="https://shop.example/.well-known/oauth-protected-resource/mcp"'));
    }

    private function apiRequest(string $token, string $url = self::API, ?KeyPair $key = null, ?string $ath = null): ServerRequestInterface
    {
        $overrides = $ath !== null ? ['ath' => $ath] : [];

        return (new ServerRequest('GET', $url))
            ->withHeader('Authorization', 'DPoP ' . $token)
            ->withHeader('DPoP', $this->agent->dpopProof('GET', $url, $this->company->clock->now(), $token, $overrides, $key));
    }

    private function refused(ServerRequestInterface $request): PoppyError
    {
        try {
            $this->company->server->resourceGuard()->authenticate($request, self::API);
        } catch (PoppyError $error) {
            return $error;
        }

        self::fail('expected the request to be refused');
    }
}
