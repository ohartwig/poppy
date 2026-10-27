<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Server;

use Koh\Poppy\Discovery\Api;
use Koh\Poppy\Server\Endpoints;
use Koh\Poppy\Server\ServerConfiguration;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ServerConfigurationTest extends TestCase
{
    private const ISSUER = 'https://shop.example/poppy';

    public function testDefaults(): void
    {
        $configuration = new ServerConfiguration(self::ISSUER, ['shop.example'], Endpoints::below(self::ISSUER));

        self::assertSame(3600, $configuration->sessionTokenTtl);
        self::assertSame(2592000, $configuration->sessionLifetime);
        self::assertSame(7776000, $configuration->accountTokenTtl);
        self::assertSame(120, $configuration->authorizationCodeTtl);
        self::assertSame(600, $configuration->deviceCodeTtl);
        self::assertSame(5, $configuration->deviceInterval);
        self::assertFalse($configuration->hasDirectSignIn());
        self::assertFalse($configuration->hasDeviceSignIn());
        self::assertSame([], $configuration->grantableScopes());
    }

    public function testEndpointsBelowTheIssuer(): void
    {
        $endpoints = Endpoints::below(self::ISSUER);

        self::assertSame('https://shop.example/poppy/token', $endpoints->token);
        self::assertSame('https://shop.example/poppy/revoke', $endpoints->revocation);
        self::assertSame('https://shop.example/poppy/authorize', $endpoints->authorization);
        self::assertSame('https://shop.example/poppy/device_authorization', $endpoints->deviceAuthorization);
        self::assertSame('https://shop.example/poppy/device', $endpoints->deviceVerification);
    }

    public function testAnEndpointMustBeHttps(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Endpoints('https://a.example/t', 'https://a.example/r', 'http://a.example/a', 'https://a.example/d', 'https://a.example/v');
    }

    public function testScopesAndApis(): void
    {
        $mcp = Api::mcp('https://shop.example/mcp', 'Search', supportsDpop: false);
        $configuration = new ServerConfiguration(
            self::ISSUER,
            ['shop.example'],
            Endpoints::below(self::ISSUER),
            directScopes: ['poppy:read', 'addresses'],
            deviceScopes: ['poppy:read'],
            customScopes: ['addresses' => 'Addresses'],
            apis: [Api::openApi('https://shop.example/openapi.json', 'Orders'), $mcp],
        );

        self::assertSame(['poppy:read', 'poppy:write', 'addresses'], $configuration->knownScopes());
        self::assertSame(['poppy:read', 'addresses'], $configuration->grantableScopes());
        self::assertTrue($configuration->hasDirectSignIn());
        self::assertTrue($configuration->hasDeviceSignIn());
        self::assertSame($mcp, $configuration->apiForResource('https://shop.example/mcp'));
        self::assertNull($configuration->apiForResource('https://shop.example/openapi.json'), 'an OpenAPI API without resource is not a resource');
    }

    public function testAnEmptyScopeListIsOff(): void
    {
        $configuration = new ServerConfiguration(self::ISSUER, ['shop.example'], Endpoints::below(self::ISSUER), directScopes: [], deviceScopes: []);

        self::assertFalse($configuration->hasDirectSignIn());
        self::assertFalse($configuration->hasDeviceSignIn());
    }

    /** @return iterable<string, array{\Closure(): ServerConfiguration}> */
    public static function invalid(): iterable
    {
        $e = Endpoints::below(self::ISSUER);
        yield 'http issuer' => [static fn () => new ServerConfiguration('http://shop.example/poppy', ['shop.example'], $e)];
        yield 'issuer with query' => [static fn () => new ServerConfiguration('https://shop.example/poppy?x=1', ['shop.example'], $e)];
        yield 'issuer with trailing slash' => [static fn () => new ServerConfiguration('https://shop.example/poppy/', ['shop.example'], $e)];
        yield 'no domain' => [static fn () => new ServerConfiguration(self::ISSUER, [], $e)];
        yield 'custom scope in the poppy namespace' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, customScopes: ['poppy:extra' => 'x'])];
        yield 'custom scope with a space' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, customScopes: ['a b' => 'x'])];
        yield 'direct grants an undeclared scope' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, directScopes: ['orders'])];
        yield 'device grants an undeclared scope' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, deviceScopes: ['orders'])];
        yield 'session token too short' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, sessionTokenTtl: 59)];
        yield 'session token too long' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, sessionTokenTtl: 86401)];
        yield 'code too short' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, authorizationCodeTtl: 29)];
        yield 'code too long' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, authorizationCodeTtl: 601)];
    }

    /** @param \Closure(): ServerConfiguration $build */
    #[DataProvider('invalid')]
    public function testRefusesInvalidConfiguration(\Closure $build): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $build();
    }

    /** @return iterable<string, array{\Closure(): ServerConfiguration}> */
    public static function boundaries(): iterable
    {
        $e = Endpoints::below(self::ISSUER);
        yield 'shortest session token' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, sessionTokenTtl: 60)];
        yield 'longest session token' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, sessionTokenTtl: 86400)];
        yield 'shortest code' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, authorizationCodeTtl: 30)];
        yield 'longest code' => [static fn () => new ServerConfiguration(self::ISSUER, ['shop.example'], $e, authorizationCodeTtl: 600)];
        yield 'issuer without path' => [static fn () => new ServerConfiguration('https://shop.example', ['shop.example'], $e)];
    }

    /** @param \Closure(): ServerConfiguration $build */
    #[DataProvider('boundaries')]
    public function testAcceptsTheBoundaries(\Closure $build): void
    {
        self::assertInstanceOf(ServerConfiguration::class, $build());
    }
}
