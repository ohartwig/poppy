<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

/**
 * A Direct Sign-In the User approved, waiting to be exchanged (Poppy 0.2,
 * 4.5). Single use: the storage hands it out once and deletes it.
 */
final readonly class AuthorizationCode
{
    /** @param list<string> $scopes the scopes the User approved */
    public function __construct(
        public string $hash,
        public string $clientId,
        public string $redirectUri,
        public string $codeChallenge,
        public string $accountId,
        public array $scopes,
        public \DateTimeImmutable $expiresAt,
    ) {}
}
