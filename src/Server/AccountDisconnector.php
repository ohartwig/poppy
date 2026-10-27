<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;

/**
 * Revokes Account Tokens: when a Personal Agent signs out, and when the User
 * disconnects it from their account settings (Poppy 0.2, 4.9).
 *
 * Both end the same way — the token is revoked and every Session signed in
 * under it continues signed out — so the account pages of the integrations
 * call this instead of touching storage themselves.
 */
final readonly class AccountDisconnector
{
    public function __construct(
        private PoppyStorage $storage,
        private ClockInterface $clock,
    ) {}

    public function revoke(AccountToken $token): void
    {
        $this->storage->saveAccountToken($token->revoke($this->clock->now()));
        $this->storage->signOutSessions($token->id);
    }

    /**
     * The Personal Agents connected to an account: one entry per client_id,
     * with the Account Tokens that are still usable.
     *
     * @return array<string, list<AccountToken>>
     */
    public function connections(string $accountId): array
    {
        $now = $this->clock->now();
        $connections = [];
        foreach ($this->storage->findAccountTokensForAccount($accountId) as $token) {
            if ($token->isUsable($now)) {
                $connections[$token->clientId][] = $token;
            }
        }

        return $connections;
    }

    /** Disconnects one Personal Agent from an account: every token it holds for it. */
    public function disconnect(string $accountId, string $clientId): void
    {
        foreach ($this->connections($accountId)[$clientId] ?? [] as $token) {
            $this->revoke($token);
        }
    }
}
