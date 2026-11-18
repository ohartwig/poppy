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
 *
 * A device authorization is the one record two requests write while it is
 * pending: the Personal Agent's poll and the User's decision. Its three
 * transition methods — recordDevicePoll(), approveDeviceAuthorization() and
 * denyDeviceAuthorization() — therefore write only their own columns and only
 * while the record is still pending, in one conditional statement. Writing
 * back a record read earlier would let a poll undo an approval, or a second
 * approval re-arm a device code that was already used.
 *
 * Every other method is ordinary read and write.
 *
 * Token values are never passed in: lookups use the SHA-256 hash, so a
 * database dump contains no usable token.
 */
interface PoppyStorage
{
    /** Stores a new Session. A sign-in goes through signInSession(), a sign-out through signOutSessions(). */
    public function saveSession(Session $session): void;

    public function findSession(string $id): ?Session;

    /**
     * Signs a Session in under an Account Token, atomically: sets the account,
     * the token and the scopes in one conditional statement. False when the
     * Session does not exist or was ever signed in to another account (4.4);
     * nothing is written then.
     *
     * The condition belongs in the statement. A Session read earlier may have
     * been signed in to another account since.
     *
     * @param list<string> $scopes
     */
    public function signInSession(string $sessionId, AccountToken $token, array $scopes): bool;

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

    /** Stores a new device authorization. Later changes go through the transition methods below. */
    public function saveDeviceAuthorization(DeviceAuthorization $authorization): void;

    public function findDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization;

    public function findDeviceAuthorizationByUserCode(string $userCode): ?DeviceAuthorization;

    /**
     * Records a poll: sets the last poll time and the interval, and nothing
     * else. Does nothing unless the authorization is still pending.
     */
    public function recordDevicePoll(string $deviceCodeHash, \DateTimeImmutable $at, int $interval): void;

    /**
     * Moves a pending authorization to approved, atomically; false unless it was pending.
     *
     * @param list<string> $grantedScopes
     */
    public function approveDeviceAuthorization(string $deviceCodeHash, string $accountId, array $grantedScopes): bool;

    /** Moves a pending authorization to denied, atomically; false unless it was pending. */
    public function denyDeviceAuthorization(string $deviceCodeHash): bool;

    /** Moves an approved authorization to consumed, atomically; null unless it was approved. */
    public function consumeApprovedDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization;

    /**
     * Withdraws what one Personal Agent was approved for on one account but
     * has not exchanged yet: removes its authorization codes and moves its
     * approved device authorizations to denied. Called when the User
     * disconnects the agent, so a sign-in approved a minute earlier cannot be
     * turned into a new Account Token afterwards.
     */
    public function cancelApprovedSignIns(string $accountId, string $clientId): void;

    /** Removes expired records. Called from a scheduled task, never on the request path. */
    public function purgeExpired(\DateTimeImmutable $now): void;
}
