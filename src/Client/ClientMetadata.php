<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

use Koh\Poppy\Http\Url;
use Koh\Poppy\Jose\JwkSet;

/**
 * A Personal Agent as its client metadata document describes it (Poppy 0.2,
 * 4.1; OAuth Client ID Metadata Document draft).
 *
 * Only what the server acts on is kept. The name and logo are shown on the
 * sign-in pages, so they are display data from an unauthenticated source and
 * must be escaped like any other input.
 */
final readonly class ClientMetadata
{
    /**
     * @param list<string>                    $redirectUris
     * @param array<string, array<mixed>> $extensions
     */
    public function __construct(
        public string $clientId,
        public ?string $clientName,
        public ?string $logoUri,
        public string $jwksUri,
        public array $redirectUris,
        public array $extensions,
        public JwkSet $keys,
    ) {}

    public function allowsRedirectUri(string $redirectUri): bool
    {
        // Exact string comparison (4.5): no normalization, no prefix matching.
        return in_array($redirectUri, $this->redirectUris, true);
    }

    public function supportsExtension(string $name): bool
    {
        return isset($this->extensions[$name]);
    }

    /** The name to show a User: the declared name, or the client_id's host when there is none. */
    public function displayName(): string
    {
        return $this->clientName ?? (string) Url::host($this->clientId);
    }
}
