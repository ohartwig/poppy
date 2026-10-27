<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

/**
 * The record behind a Session Token (Poppy 0.2, 4.2 and 4.3).
 *
 * A DPoP token carries the thumbprint of the key it is bound to. A Bearer
 * token exists only for an MCP server without DPoP and carries that server's
 * URL as its resource; it is accepted nowhere else.
 *
 * `accountTokenId` records which sign-in the token was issued under. A
 * request is handled as signed in only while the Session is still signed in
 * under that same sign-in, so a sign-out takes effect on the next request
 * instead of when the token runs out (4.9).
 */
final readonly class SessionToken
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $hash,
        public string $sessionId,
        public string $clientId,
        public string $userId,
        public TokenType $type,
        public ?string $jkt,
        public ?string $resource,
        public array $scopes,
        public ?string $accountTokenId,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
    ) {}

    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }
}
