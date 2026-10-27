<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\SignIn;

use Koh\Poppy\Client\ClientMetadata;

/**
 * A validated Direct Sign-In request, ready for the consent page.
 *
 * The integration keeps it across the User's sign-in — typically serialized
 * into the server-side session as toArray() — and passes it back to
 * DirectSignIn::approve() or ::deny(). Nothing in it is a secret, but it must
 * not round-trip through the browser, where the redirect URI could be edited.
 */
final readonly class AuthorizationRequest
{
    /** @param list<string> $scopes */
    public function __construct(
        public ClientMetadata $client,
        public string $redirectUri,
        public array $scopes,
        public string $codeChallenge,
        public ?string $state,
    ) {}

    /** @return array{client_id: string, redirect_uri: string, scope: list<string>, code_challenge: string, state: string|null} */
    public function toArray(): array
    {
        return [
            'client_id' => $this->client->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $this->scopes,
            'code_challenge' => $this->codeChallenge,
            'state' => $this->state,
        ];
    }
}
