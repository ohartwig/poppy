<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

use Koh\Poppy\Exception\FetchFailed;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Http\JsonFetcher;
use Koh\Poppy\Http\Url;
use Koh\Poppy\Jose\JwkSet;

/**
 * Fetches and checks a Personal Agent's client metadata document and key set.
 *
 * The rules are those of Poppy 0.2, 4.1: the document's `client_id` equals the
 * URL it came from, `jwks_uri` and every redirect URI are HTTPS on the same
 * domain as the `client_id`, and the agent authenticates with
 * `private_key_jwt`. "Same domain" is read as the client_id's host or a
 * subdomain of it — the reading that never lets a document point at a host its
 * publisher may not control.
 */
final readonly class ClientMetadataResolver
{
    private const MAX_REDIRECT_URIS = 16;

    public function __construct(private JsonFetcher $fetcher) {}

    /** @throws InvalidClientMetadata */
    public function resolve(string $clientId): ClientMetadata
    {
        if (!Url::isHttps($clientId)) {
            throw InvalidClientMetadata::because('client_id is not an HTTPS URL');
        }

        try {
            $document = $this->fetcher->fetch($clientId);
        } catch (FetchFailed $exception) {
            throw InvalidClientMetadata::because('client metadata could not be fetched: ' . $exception->getMessage(), $exception);
        }

        if (($document['client_id'] ?? null) !== $clientId) {
            throw InvalidClientMetadata::because('client_id in the document differs from the URL it was fetched from');
        }

        $authMethod = $document['token_endpoint_auth_method'] ?? 'private_key_jwt';
        if ($authMethod !== 'private_key_jwt') {
            throw InvalidClientMetadata::because('token_endpoint_auth_method must be private_key_jwt');
        }

        $clientHost = (string) Url::host($clientId);

        $jwksUri = $document['jwks_uri'] ?? null;
        if (!is_string($jwksUri) || !Url::isHttps($jwksUri) || !Url::isOnDomain($jwksUri, $clientHost)) {
            throw InvalidClientMetadata::because('jwks_uri must be an HTTPS URL on the client_id\'s domain');
        }

        $redirectUris = $document['redirect_uris'] ?? [];
        if (!is_array($redirectUris) || !array_is_list($redirectUris) || count($redirectUris) > self::MAX_REDIRECT_URIS) {
            throw InvalidClientMetadata::because('redirect_uris must be a list');
        }
        foreach ($redirectUris as $redirectUri) {
            if (!is_string($redirectUri) || !Url::isHttps($redirectUri) || !Url::isOnDomain($redirectUri, $clientHost)) {
                throw InvalidClientMetadata::because('every redirect URI must be an HTTPS URL on the client_id\'s domain');
            }
        }

        $logoUri = $document['logo_uri'] ?? null;
        if (!is_string($logoUri) || !Url::isHttps($logoUri)) {
            $logoUri = null;
        }

        $clientName = $document['client_name'] ?? null;
        $clientName = is_string($clientName) && trim($clientName) !== '' ? mb_substr(trim($clientName), 0, 100) : null;

        $extensions = [];
        $declared = $document['extensions'] ?? [];
        if (is_array($declared)) {
            foreach ($declared as $name => $extension) {
                if (is_string($name) && is_array($extension)) {
                    $extensions[$name] = $extension;
                }
            }
        }

        try {
            $keys = JwkSet::fromArray($this->fetcher->fetch($jwksUri));
        } catch (FetchFailed $exception) {
            throw InvalidClientMetadata::because('key set could not be fetched: ' . $exception->getMessage(), $exception);
        } catch (InvalidJose $exception) {
            throw InvalidClientMetadata::because($exception->getMessage(), $exception);
        }

        /** @var list<string> $redirectUris */
        return new ClientMetadata($clientId, $clientName, $logoUri, $jwksUri, $redirectUris, $extensions, $keys);
    }
}
