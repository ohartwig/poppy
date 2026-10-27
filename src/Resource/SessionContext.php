<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Resource;

use Koh\Poppy\Exception\PoppyError;

/**
 * Who an API or conversation request comes from: always a known Personal
 * Agent and User (Poppy 0.2, section 6), and an account when signed in.
 */
final readonly class SessionContext
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $sessionId,
        public string $clientId,
        public string $userId,
        public ?string $accountId,
        public array $scopes,
    ) {}

    public function isSignedIn(): bool
    {
        return $this->accountId !== null;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * @throws PoppyError sign_in_required (403) or insufficient_scope (403)
     */
    public function requireScopes(string ...$scopes): string
    {
        if ($this->accountId === null) {
            throw PoppyError::signInRequired();
        }

        $missing = array_values(array_diff($scopes, $this->scopes));
        if ($missing !== []) {
            throw PoppyError::insufficientScope(array_values($scopes));
        }

        return $this->accountId;
    }
}
