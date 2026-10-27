<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Http;

use Koh\Poppy\Exception\FetchFailed;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Fetches a JSON document a Personal Agent published: its client metadata or
 * its key set.
 *
 * Redirects are an error, not something to follow. The client metadata
 * document must be served at the very URL that is the `client_id`, and a key
 * set that moves is a key set somebody else may now be serving. The PSR-18
 * client must therefore be configured not to follow redirects; Guzzle does by
 * default, which is why the integrations build their own client.
 */
final readonly class JsonFetcher
{
    private const MAX_BYTES = 65536;

    private const DEFAULT_TTL = 300;

    private const MIN_TTL = 60;

    private const MAX_TTL = 86400;

    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
        private AddressGuard $addressGuard,
        private ?DocumentCache $cache = null,
    ) {}

    /**
     * @return array<string, mixed>
     *
     * @throws FetchFailed
     */
    public function fetch(string $url): array
    {
        $cacheKey = 'poppy-doc-' . hash('sha256', $url);
        $cached = $this->cache?->get($cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        $this->addressGuard->assertAllowed($url);

        $request = $this->requestFactory->createRequest('GET', $url)->withHeader('Accept', 'application/json');

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            throw FetchFailed::transport($exception);
        }

        if ($response->getStatusCode() !== 200) {
            throw FetchFailed::status($response->getStatusCode());
        }

        $body = $response->getBody();
        $content = '';
        while (!$body->eof()) {
            $content .= $body->read(8192);
            if (strlen($content) > self::MAX_BYTES) {
                throw FetchFailed::tooLarge();
            }
        }

        try {
            $document = json_decode($content, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw FetchFailed::notJson();
        }
        if (!is_array($document) || ($document !== [] && array_is_list($document))) {
            throw FetchFailed::notJson();
        }

        /** @var array<string, mixed> $document */
        $this->cache?->set($cacheKey, $document, self::ttl($response->getHeaderLine('Cache-Control')));

        return $document;
    }

    /** Honours max-age within bounds; no-store and no-cache still get the minimum, or every token request would refetch. */
    private static function ttl(string $cacheControl): int
    {
        if (preg_match('/(?:^|[,\s])max-age\s*=\s*"?(\d+)"?/i', $cacheControl, $match) !== 1) {
            return self::DEFAULT_TTL;
        }

        return max(self::MIN_TTL, min(self::MAX_TTL, (int) $match[1]));
    }
}
