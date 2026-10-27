<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

/**
 * One User's activity at this Company through one Personal Agent (Poppy 0.2,
 * section 4).
 *
 * `accountId` is the account the Session was ever signed in to and never
 * changes once set: a Session that signed out can sign in again only to the
 * same account (4.4). `accountTokenId` is the sign-in that is current now, or
 * null when the Session is signed out.
 */
final readonly class Session
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $id,
        public string $clientId,
        public string $userId,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $expiresAt,
        public ?string $accountId = null,
        public ?string $accountTokenId = null,
        public array $scopes = [],
    ) {}

    public function isActive(\DateTimeImmutable $now): bool
    {
        return $now < $this->expiresAt;
    }

    public function isSignedIn(): bool
    {
        return $this->accountTokenId !== null;
    }

    public function belongsTo(string $clientId, string $userId): bool
    {
        return hash_equals($this->clientId, $clientId) && hash_equals($this->userId, $userId);
    }

    /** @param list<string> $scopes */
    public function signIn(AccountToken $token, array $scopes): self
    {
        return new self($this->id, $this->clientId, $this->userId, $this->createdAt, $this->expiresAt, $token->accountId, $token->id, $scopes);
    }

    public function signOut(): self
    {
        return new self($this->id, $this->clientId, $this->userId, $this->createdAt, $this->expiresAt, $this->accountId);
    }
}
