<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

/** A Personal Agent that proved, with a client assertion, that it holds a key from its key set. */
final readonly class AuthenticatedClient
{
    public function __construct(public ClientMetadata $metadata) {}

    public function clientId(): string
    {
        return $this->metadata->clientId;
    }
}
