<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Client;

use Koh\Poppy\Client\ClientMetadataResolver;
use Koh\Poppy\Client\ListClientPolicy;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Http\JsonFetcher;
use Koh\Poppy\Http\PublicAddressGuard;
use Koh\Poppy\Tests\Support\FakeHttpClient;
use Koh\Poppy\Tests\Support\PersonalAgent;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientMetadataResolverTest extends TestCase
{
    private FakeHttpClient $http;

    private PersonalAgent $agent;

    protected function setUp(): void
    {
        $this->http = new FakeHttpClient();
        $this->agent = new PersonalAgent();
    }

    public function testReadsWhatTheServerActsOn(): void
    {
        $this->agent->publish($this->http, [
            'client_name' => '  Example Agent  ',
            'redirect_uris' => ['https://agent.example/cb', 'https://app.agent.example/cb'],
            'extensions' => ['operations' => ['version' => '1'], 'broken' => 'x', 5 => ['version' => '1']],
        ]);

        $metadata = $this->resolver()->resolve($this->agent->clientId);

        self::assertSame('Example Agent', $metadata->clientName);
        self::assertSame('Example Agent', $metadata->displayName());
        self::assertSame('https://agent.example/logo.png', $metadata->logoUri);
        self::assertSame($this->agent->jwksUri, $metadata->jwksUri);
        self::assertTrue($metadata->allowsRedirectUri('https://app.agent.example/cb'));
        self::assertFalse($metadata->allowsRedirectUri('https://agent.example/cb/'), 'exact match only');
        self::assertTrue($metadata->supportsExtension('operations'));
        self::assertFalse($metadata->supportsExtension('broken'));
        self::assertCount(1, $metadata->extensions);
        self::assertCount(1, $metadata->keys->keys);
    }

    public function testFallsBackToTheHostForDisplayAndDropsAnUnsafeLogo(): void
    {
        $this->agent->publish($this->http, ['client_name' => '   ', 'logo_uri' => 'http://agent.example/logo.png']);

        $metadata = $this->resolver()->resolve($this->agent->clientId);

        self::assertNull($metadata->clientName);
        self::assertSame('agent.example', $metadata->displayName());
        self::assertNull($metadata->logoUri);
    }

    public function testCutsAnOverlongName(): void
    {
        $this->agent->publish($this->http, ['client_name' => str_repeat('ä', 150)]);

        self::assertSame(100, mb_strlen((string) $this->resolver()->resolve($this->agent->clientId)->clientName));
    }

    public function testAMissingAuthMethodMeansPrivateKeyJwt(): void
    {
        $this->agent->publish($this->http);
        $document = ['client_id' => $this->agent->clientId, 'jwks_uri' => $this->agent->jwksUri];
        $this->http->serveJson($this->agent->clientId, $document);

        self::assertSame([], $this->resolver()->resolve($this->agent->clientId)->redirectUris);
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalid(): iterable
    {
        yield 'other auth method' => [['token_endpoint_auth_method' => 'none'], 'private_key_jwt'];
        yield 'jwks on http' => [['jwks_uri' => 'http://agent.example/jwks.json'], 'jwks_uri'];
        yield 'jwks missing' => [['jwks_uri' => null], 'jwks_uri'];
        yield 'redirect URIs not a list' => [['redirect_uris' => ['a' => 'https://agent.example/cb']], 'redirect_uris'];
        yield 'redirect URIs a string' => [['redirect_uris' => 'https://agent.example/cb'], 'redirect_uris'];
        yield 'too many redirect URIs' => [['redirect_uris' => array_fill(0, 17, 'https://agent.example/cb')], 'redirect_uris'];
        yield 'redirect URI off the domain' => [['redirect_uris' => ['https://evil.example/cb']], 'redirect URI'];
        yield 'redirect URI on http' => [['redirect_uris' => ['http://agent.example/cb']], 'redirect URI'];
        yield 'redirect URI not a string' => [['redirect_uris' => [5]], 'redirect URI'];
    }

    /** @param array<string, mixed> $overrides */
    #[DataProvider('invalid')]
    public function testRefusesInvalidDocuments(array $overrides, string $message): void
    {
        $this->agent->publish($this->http, $overrides);

        $this->expectException(InvalidClientMetadata::class);
        $this->expectExceptionMessage($message);
        $this->resolver()->resolve($this->agent->clientId);
    }

    public function testExactlySixteenRedirectUrisAreFine(): void
    {
        $this->agent->publish($this->http, ['redirect_uris' => array_fill(0, 16, 'https://agent.example/cb')]);

        self::assertCount(16, $this->resolver()->resolve($this->agent->clientId)->redirectUris);
    }

    public function testRefusesAClientIdThatIsNotHttps(): void
    {
        $this->expectExceptionMessage('client_id is not an HTTPS URL');
        $this->resolver()->resolve('http://agent.example/agent.json');
    }

    public function testReportsAnUnreachableDocumentOrKeySet(): void
    {
        try {
            $this->resolver()->resolve($this->agent->clientId);
            self::fail('expected a failure');
        } catch (InvalidClientMetadata $exception) {
            self::assertStringStartsWith('client metadata could not be fetched', $exception->getMessage());
        }

        $this->agent->publish($this->http);
        $this->http->serve($this->agent->jwksUri, new \Nyholm\Psr7\Response(500));
        $this->expectExceptionMessage('key set could not be fetched');
        $this->resolver()->resolve($this->agent->clientId);
    }

    public function testReportsAKeySetWithoutUsableKeys(): void
    {
        $this->agent->publish($this->http);
        $this->http->serveJson($this->agent->jwksUri, ['keys' => [['kty' => 'oct', 'k' => 'eA']]]);

        $this->expectExceptionMessage('no usable signature key');
        $this->resolver()->resolve($this->agent->clientId);
    }

    public function testListPolicy(): void
    {
        $open = new ListClientPolicy();
        $blocked = new ListClientPolicy(block: ['https://agent.example/agent.json']);
        $allowed = new ListClientPolicy(allow: ['agent.example']);

        self::assertTrue($open->accepts('https://anything.example/a.json'));
        self::assertFalse($blocked->accepts('https://agent.example/agent.json'));
        self::assertTrue($blocked->accepts('https://agent.example/other.json'), 'a full URL blocks exactly that client_id');
        self::assertTrue($allowed->accepts('https://eu.agent.example/a.json'));
        self::assertFalse($allowed->accepts('https://other.example/a.json'));
    }

    private function resolver(): ClientMetadataResolver
    {
        return new ClientMetadataResolver(new JsonFetcher($this->http, new Psr17Factory(), new PublicAddressGuard(static fn (): array => ['93.184.216.34'])));
    }
}
