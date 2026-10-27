<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Http;

use Koh\Poppy\Exception\FetchFailed;
use Koh\Poppy\Http\JsonFetcher;
use Koh\Poppy\Http\PublicAddressGuard;
use Koh\Poppy\Tests\Support\FakeHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PublicAddressGuardTest extends TestCase
{
    /** @return iterable<string, array{string, bool}> */
    public static function addresses(): iterable
    {
        yield 'public IPv4' => ['93.184.216.34', true];
        yield 'public IPv6' => ['2606:2800:220:1:248:1893:25c8:1946', true];
        yield 'loopback' => ['127.0.0.1', false];
        yield 'private 10/8' => ['10.1.2.3', false];
        yield 'private 192.168/16' => ['192.168.1.1', false];
        yield 'link-local (cloud metadata)' => ['169.254.169.254', false];
        yield 'carrier-grade NAT' => ['100.64.0.1', false];
        yield 'unspecified' => ['0.0.0.0', false];
        yield 'IPv6 loopback' => ['::1', false];
        yield 'IPv6 unique local' => ['fd00::1', false];
        yield 'IPv6 link-local' => ['fe80::1', false];
        yield 'IPv4-mapped loopback' => ['::ffff:127.0.0.1', false];
        yield 'NAT64' => ['64:ff9b::a00:1', false];
        yield 'multicast' => ['224.0.0.1', false];
        yield 'last unicast IPv4' => ['223.255.255.255', true];
        yield 'broadcast' => ['255.255.255.255', false];
        yield 'below carrier-grade NAT' => ['100.63.255.255', true];
        yield 'top of carrier-grade NAT' => ['100.127.255.255', false];
        yield 'above carrier-grade NAT' => ['100.128.0.1', true];
        yield 'IPv6 unique local, fc half' => ['fc00::1', false];
        yield 'IPv6 unique local, top' => ['fdff:ffff::1', false];
        yield 'IPv6 just below unique local' => ['fbff::1', true];
        yield 'IPv6 top of link-local' => ['febf::1', false];
        yield 'IPv6 site-local' => ['fec0::1', false];
        yield 'IPv6 top of site-local' => ['feff::1', false];
        yield 'IPv6 multicast' => ['ff02::1', false];
        yield 'IPv6 documentation' => ['2001:db8::1', false];
        yield 'IPv6 just above documentation' => ['2001:db9::1', true];
        yield 'IPv4-mapped public (refused: reach it directly)' => ['::ffff:93.184.216.34', false];
        yield 'NAT64 public' => ['64:ff9b::5db8:d822', false];
        yield 'not an address' => ['shop.example', false];
    }

    public function testAcceptsAPublicHostOnTheDefaultPort(): void
    {
        $resolved = [];
        $guard = new PublicAddressGuard(static function (string $host) use (&$resolved): array {
            $resolved[] = $host;

            return ['93.184.216.34'];
        });

        $guard->assertAllowed('https://Agent.example:443/agent.json');
        self::assertSame(['agent.example'], $resolved);
    }

    public function testALiteralAddressIsJudgedWithoutResolving(): void
    {
        $guard = new PublicAddressGuard(static fn (): array => throw new \LogicException('must not resolve'));

        $guard->assertAllowed('https://93.184.216.34/agent.json');
        $guard->assertAllowed('https://[2606:2800:220:1:248:1893:25c8:1946]/agent.json');
        $this->expectException(FetchFailed::class);
        $guard->assertAllowed('https://10.0.0.1/agent.json');
    }

    public function testAHostThatDoesNotResolveIsRefused(): void
    {
        $guard = new PublicAddressGuard(static fn (): array => []);

        $this->expectExceptionMessage('does not resolve');
        $guard->assertAllowed('https://agent.example/agent.json');
    }

    #[DataProvider('addresses')]
    public function testClassifiesAddresses(string $address, bool $public): void
    {
        self::assertSame($public, PublicAddressGuard::isPublic($address));
    }

    public function testRefusesAHostThatResolvesToAnyPrivateAddress(): void
    {
        $guard = new PublicAddressGuard(static fn (): array => ['93.184.216.34', '10.0.0.1']);

        $this->expectException(FetchFailed::class);
        $guard->assertAllowed('https://agent.example/agent.json');
    }

    public function testRefusesPlainHttpAndOtherPorts(): void
    {
        $guard = new PublicAddressGuard(static fn (): array => ['93.184.216.34']);

        foreach (['http://agent.example/agent.json', 'https://agent.example:8443/agent.json', 'https://[::1]/x'] as $url) {
            try {
                $guard->assertAllowed($url);
                self::fail($url . ' should be refused');
            } catch (FetchFailed) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testTheFetcherDoesNotFollowRedirects(): void
    {
        $http = new FakeHttpClient();
        $http->serve('https://agent.example/agent.json', new Response(302, ['Location' => 'https://agent.example/other.json']));

        $this->expectExceptionMessage('Unexpected HTTP status 302');
        $this->fetcher($http)->fetch('https://agent.example/agent.json');
    }

    public function testTheFetcherAsksForJsonAndRefusesLargeOrNonObjectBodies(): void
    {
        $http = new FakeHttpClient();
        $http->serve('https://agent.example/big', new Response(200, [], str_repeat(' ', 65537)));
        $http->serve('https://agent.example/list', new Response(200, [], '[1,2]'));
        $http->serve('https://agent.example/broken', new Response(200, [], '{'));
        $http->serve('https://agent.example/exact', new Response(200, [], '{"a":1}' . str_repeat(' ', 65536 - 7)));
        $fetcher = $this->fetcher($http);

        self::assertSame(['a' => 1], $fetcher->fetch('https://agent.example/exact'), 'exactly the limit is fine');

        foreach (['big' => 'size limit', 'list' => 'not a JSON object', 'broken' => 'not a JSON object'] as $path => $message) {
            try {
                $fetcher->fetch('https://agent.example/' . $path);
                self::fail($path . ' should fail');
            } catch (FetchFailed $exception) {
                self::assertStringContainsString($message, $exception->getMessage());
            }
        }
    }

    public function testTheFetcherCachesWithinBounds(): void
    {
        $http = new FakeHttpClient();
        $http->serveJson('https://agent.example/a', ['a' => 1], 'public, max-age=5');
        $http->serveJson('https://agent.example/b', ['b' => 1], 'max-age=999999');
        $http->serveJson('https://agent.example/c', ['c' => 1], 'no-store');
        $cache = new class implements \Koh\Poppy\Http\DocumentCache {
            /** @var array<string, array{array<string, mixed>, int}> */
            public array $entries = [];

            public function get(string $key): ?array
            {
                return $this->entries[$key][0] ?? null;
            }

            public function set(string $key, array $document, int $ttl): void
            {
                $this->entries[$key] = [$document, $ttl];
            }
        };
        $fetcher = new JsonFetcher($http, new Psr17Factory(), new PublicAddressGuard(static fn (): array => ['93.184.216.34']), $cache);

        $fetcher->fetch('https://agent.example/a');
        $fetcher->fetch('https://agent.example/a');
        $fetcher->fetch('https://agent.example/b');
        $fetcher->fetch('https://agent.example/c');

        self::assertSame(['https://agent.example/a', 'https://agent.example/b', 'https://agent.example/c'], $http->requested, 'the second fetch of a came from the cache');
        self::assertSame([60, 86400, 300], array_map(static fn (array $entry): int => $entry[1], array_values($cache->entries)));
        self::assertArrayHasKey('poppy-doc-' . hash('sha256', 'https://agent.example/a'), $cache->entries);
    }

    public function testTheFetcherSendsAnAcceptHeader(): void
    {
        $seen = [];
        $client = new class($seen) implements \Psr\Http\Client\ClientInterface {
            /** @param list<string> $seen */
            public function __construct(private array &$seen) {}

            public function sendRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                $this->seen[] = $request->getMethod() . ' ' . $request->getHeaderLine('Accept');

                return new Response(200, [], '{}');
            }
        };

        $this->fetcher($client)->fetch('https://agent.example/x');
        self::assertSame(['GET application/json'], $seen);
    }

    public function testATransportErrorIsAFetchFailure(): void
    {
        $client = new class implements \Psr\Http\Client\ClientInterface {
            public function sendRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                throw new class('down') extends \RuntimeException implements \Psr\Http\Client\ClientExceptionInterface {};
            }
        };

        $this->expectExceptionMessage('The request failed.');
        $this->fetcher($client)->fetch('https://agent.example/x');
    }

    private function fetcher(\Psr\Http\Client\ClientInterface $client): JsonFetcher
    {
        return new JsonFetcher($client, new Psr17Factory(), new PublicAddressGuard(static fn (): array => ['93.184.216.34']));
    }
}
