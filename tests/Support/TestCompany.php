<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Support;

use Koh\Poppy\Client\ListClientPolicy;
use Koh\Poppy\Discovery\Api;
use Koh\Poppy\Dpop\TimeSlotNonceSource;
use Koh\Poppy\Http\JsonFetcher;
use Koh\Poppy\Http\PublicAddressGuard;
use Koh\Poppy\PoppyServer;
use Koh\Poppy\Replay\InMemoryReplayGuard;
use Koh\Poppy\Server\Endpoints;
use Koh\Poppy\Server\NoRateLimit;
use Koh\Poppy\Server\RateLimiter;
use Koh\Poppy\Server\Scopes;
use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Server\Storage\InMemoryStorage;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/** A Company with every feature on, served from memory. */
final class TestCompany
{
    public const ISSUER = 'https://shop.example/poppy';

    public const MCP = 'https://shop.example/mcp';

    public const DPOP_MCP = 'https://shop.example/mcp-dpop';

    public const OPENAPI = 'https://shop.example/openapi.json';

    public readonly FrozenClock $clock;

    public readonly FakeHttpClient $http;

    public readonly InMemoryStorage $storage;

    public readonly ServerConfiguration $configuration;

    public readonly PoppyServer $server;

    /** @param list<string> $blocked */
    public function __construct(array $blocked = [], ?ServerConfiguration $configuration = null, ?RateLimiter $rateLimiter = null, bool $nonces = false)
    {
        $this->clock = new FrozenClock();
        $this->http = new FakeHttpClient();
        $this->storage = new InMemoryStorage();
        $this->configuration = $configuration ?? new ServerConfiguration(
            self::ISSUER,
            ['shop.example'],
            Endpoints::below(self::ISSUER),
            directScopes: [Scopes::READ, Scopes::WRITE, 'addresses'],
            deviceScopes: [Scopes::READ],
            customScopes: ['addresses' => 'Manage saved shipping addresses'],
            apis: [
                Api::openApi(self::OPENAPI, 'Orders and returns'),
                Api::mcp(self::MCP, 'Product search', supportsDpop: false),
                Api::mcp(self::DPOP_MCP, 'Product search with DPoP', supportsDpop: true),
            ],
        );

        $factory = new Psr17Factory();
        $this->server = new PoppyServer(
            $this->configuration,
            $this->storage,
            new InMemoryReplayGuard(),
            new ListClientPolicy(block: $blocked),
            new JsonFetcher($this->http, $factory, new PublicAddressGuard(static fn (): array => ['93.184.216.34'])),
            $this->clock,
            $factory,
            $factory,
            $rateLimiter ?? new NoRateLimit(),
            $nonces ? new TimeSlotNonceSource(str_repeat('n', 32), $this->clock) : null,
        );
    }

    /** @param array<string, string> $parameters */
    public static function form(string $url, array $parameters, ?string $dpop = null): ServerRequestInterface
    {
        $request = (new ServerRequest('POST', $url))
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody((new Psr17Factory())->createStream(http_build_query($parameters, '', '&', PHP_QUERY_RFC3986)));

        return $dpop !== null ? $request->withHeader('DPoP', $dpop) : $request;
    }

    /** @return array<string, mixed> */
    public static function json(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
        \assert(is_array($decoded));

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /** @param array<string, mixed> $body */
    public static function text(array $body, string $key): string
    {
        $value = $body[$key] ?? null;
        \assert(is_string($value), $key . ' is not a string');

        return $value;
    }

    /**
     * POSTs to the token endpoint as $agent, with client authentication and a
     * DPoP proof unless $dpop is false.
     *
     * @param array<string, string> $parameters
     */
    public function token(PersonalAgent $agent, array $parameters, bool $dpop = true): ResponseInterface
    {
        $now = $this->clock->now();
        $endpoint = $this->configuration->endpoints->token;

        return $this->server->tokenEndpoint()->handle(self::form(
            $endpoint,
            $parameters + $agent->clientAuthentication(self::ISSUER, $now),
            $dpop ? $agent->dpopProof('POST', $endpoint, $now) : null,
        ));
    }

    /**
     * @param array<string, string> $extra
     *
     * @return array<string, mixed> the token response of a fresh signed-out Session
     */
    public function startSession(PersonalAgent $agent, string $userId = 'usr_Q7c1vK', array $extra = []): array
    {
        $response = $this->token($agent, $extra + [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $agent->sessionAssertion(self::ISSUER, $userId, $this->clock->now()),
        ]);
        \assert($response->getStatusCode() === 200, (string) $response->getBody());

        return self::json($response);
    }
}
