<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

/**
 * The record behind an Account Token (Poppy 0.2, 4.4 and 4.8): which
 * Personal Agent, User ID and account it belongs to, and what it may grant.
 * Only the SHA-256 hash of the token is stored; the token itself exists only
 * in the response that issued it.
 */
final readonly class AccountToken
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $id,
        public string $hash,
        public string $clientId,
        public string $userId,
        public string $accountId,
        public array $scopes,
        public \DateTimeImmutable $issuedAt,
        public ?\DateTimeImmutable $expiresAt = null,
        public ?\DateTimeImmutable $revokedAt = null,
    ) {}

    public function isUsable(\DateTimeImmutable $now): bool
    {
        return $this->revokedAt === null && ($this->expiresAt === null || $now < $this->expiresAt);
    }

    public function revoke(\DateTimeImmutable $at): self
    {
        return new self($this->id, $this->hash, $this->clientId, $this->userId, $this->accountId, $this->scopes, $this->issuedAt, $this->expiresAt, $at);
    }
}
