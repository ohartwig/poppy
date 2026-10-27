<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Discovery;

use Koh\Poppy\Discovery\Api;
use Koh\Poppy\Discovery\AuthorizationServerMetadata;
use Koh\Poppy\Discovery\PoppyDocument;
use Koh\Poppy\Server\Endpoints;
use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Tests\Support\TestCompany;
use PHPUnit\Framework\TestCase;

final class DiscoveryTest extends TestCase
{
    public function testAWebsiteOnlyDocument(): void
    {
        $document = new PoppyDocument('Example Shop', 'shop.example');

        self::assertSame(
            '{"protocol_version":"0.2","organization":{"name":"Example Shop","domain":"shop.example"},"web":{}}',
            json_encode($document->toArray(), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        );
    }

    public function testAFullDocumentDeclaresWhatIsConfigured(): void
    {
        $company = new TestCompany();
        $document = (new PoppyDocument(
            'Example Shop',
            'shop.example',
            $company->configuration,
            $company->configuration->apis,
            browserSessionEndpoint: 'https://shop.example/poppy/browser-session',
            feedbackEndpoint: 'https://shop.example/poppy/feedback',
        ))->toArray();

        self::assertSame(['issuer' => TestCompany::ISSUER, 'direct' => ['scopes' => ['poppy:read', 'poppy:write', 'addresses']], 'device' => ['scopes' => ['poppy:read']], 'custom_scopes' => ['addresses' => 'Manage saved shipping addresses']], $document['auth']);
        self::assertSame(['browser_session_endpoint' => 'https://shop.example/poppy/browser-session'], $document['web']);
        self::assertSame(['endpoint' => 'https://shop.example/poppy/feedback'], $document['feedback']);
        self::assertIsArray($document['apis']);
        self::assertSame(['type' => 'mcp', 'url' => TestCompany::MCP, 'description' => 'Product search'], $document['apis'][1]);
    }

    public function testAnApiWithoutAuthorizationServerIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PoppyDocument('Example Shop', 'shop.example', apis: [Api::openApi('https://shop.example/openapi.json', 'Orders')]);
    }

    public function testTheIssuerMustListTheDomain(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PoppyDocument('Example Shop', 'other.example', (new TestCompany())->configuration);
    }

    public function testMetadataBindsTheIssuerToItsDomains(): void
    {
        $metadata = (new TestCompany())->server->metadata();

        self::assertSame(TestCompany::ISSUER, $metadata['issuer']);
        self::assertSame(['shop.example'], $metadata['poppy_domains']);
        self::assertSame(['https://shop.example', TestCompany::MCP, TestCompany::DPOP_MCP], $metadata['protected_resources']);
        self::assertIsArray($metadata['grant_types_supported']);
        self::assertIsArray($metadata['dpop_signing_alg_values_supported']);
        self::assertContains('urn:ietf:params:oauth:grant-type:jwt-bearer', $metadata['grant_types_supported']);
        self::assertContains('refresh_token', $metadata['grant_types_supported']);
        self::assertContains('ES256', $metadata['dpop_signing_alg_values_supported']);
        self::assertSame('https://shop.example/poppy/authorize', $metadata['authorization_endpoint']);
        self::assertSame('https://shop.example/poppy/device_authorization', $metadata['device_authorization_endpoint']);
    }

    public function testSignedOutOnlyMetadataHasNoSignInEndpoints(): void
    {
        $configuration = new ServerConfiguration(TestCompany::ISSUER, ['shop.example'], Endpoints::below(TestCompany::ISSUER));
        $metadata = AuthorizationServerMetadata::build($configuration, ['ES256'], ['ES256']);

        self::assertArrayNotHasKey('authorization_endpoint', $metadata);
        self::assertArrayNotHasKey('device_authorization_endpoint', $metadata);
        self::assertArrayNotHasKey('scopes_supported', $metadata);
        self::assertSame(['urn:ietf:params:oauth:grant-type:jwt-bearer', 'refresh_token'], $metadata['grant_types_supported']);
    }

    public function testTheMetadataUrlFollowsRfc8414(): void
    {
        self::assertSame('https://shop.example/.well-known/oauth-authorization-server/poppy', AuthorizationServerMetadata::url('https://shop.example/poppy'));
        self::assertSame('https://shop.example/.well-known/oauth-authorization-server', AuthorizationServerMetadata::url('https://shop.example'));
        self::assertSame('/.well-known/oauth-authorization-server/poppy', AuthorizationServerMetadata::path('https://shop.example/poppy'));
    }
}
