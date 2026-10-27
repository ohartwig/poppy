<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Storage;

use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\SessionToken;

/**
 * Persistence for the protocol state, implemented once per framework.
 *
 * Two methods carry a concurrency contract, and the protocol's single-use
 * guarantees rest on them: consumeAuthorizationCode() and
 * consumeApprovedDeviceAuthorization() must hand a record out at most once
 * even when two requests race — DELETE … RETURNING, or an UPDATE whose WHERE
 * clause includes the expected state and whose affected-row count decides.
 * Every other method is ordinary read and write.
 *
 * Token values are never passed in: lookups use the SHA-256 hash, so a
 * database dump contains no usable token.
 */
interface PoppyStorage
{
    public function saveSession(Session $session): void;

    public function findSession(string $id): ?Session;

    /** Signs out every Session currently signed in under this Account Token (4.9). */
    public function signOutSessions(string $accountTokenId): void;

    public function saveAccountToken(AccountToken $token): void;

    public function findAccountTokenByHash(string $hash): ?AccountToken;

    public function findAccountToken(string $id): ?AccountToken;

    /**
     * The Account Tokens one account granted, for the account page where the
     * User disconnects Personal Agents (4.9).
     *
     * @return list<AccountToken>
     */
    public function findAccountTokensForAccount(string $accountId): array;

    public function saveSessionToken(SessionToken $token): void;

    public function findSessionTokenByHash(string $hash): ?SessionToken;

    public function saveAuthorizationCode(AuthorizationCode $code): void;

    /** Returns the code and removes it, atomically; null when it does not exist or was already taken. */
    public function consumeAuthorizationCode(string $hash): ?AuthorizationCode;

    public function saveDeviceAuthorization(DeviceAuthorization $authorization): void;

    public function findDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization;

    public function findDeviceAuthorizationByUserCode(string $userCode): ?DeviceAuthorization;

    /** Moves an approved authorization to consumed, atomically; null unless it was approved. */
    public function consumeApprovedDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization;

    /** Removes expired records. Called from a scheduled task, never on the request path. */
    public function purgeExpired(\DateTimeImmutable $now): void;
}
