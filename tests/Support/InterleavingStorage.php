<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Support;

use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\AuthorizationCode;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\SessionToken;
use Koh\Poppy\Server\Storage\PoppyStorage;

/**
 * Lets a test run a second request between the read and the write of a first.
 *
 * Arm it with afterNextDeviceRead(): the next findDeviceAuthorization() reads
 * the record, then runs the callback, then returns what it read — which by
 * then is stale, exactly as it is for a request that lost a race.
 */
final class InterleavingStorage implements PoppyStorage
{
    private ?\Closure $afterDeviceRead = null;

    public function __construct(private readonly PoppyStorage $inner) {}

    /** @param \Closure(): void $concurrentRequest */
    public function afterNextDeviceRead(\Closure $concurrentRequest): void
    {
        $this->afterDeviceRead = $concurrentRequest;
    }

    public function findDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        $authorization = $this->inner->findDeviceAuthorization($deviceCodeHash);

        $concurrentRequest = $this->afterDeviceRead;
        $this->afterDeviceRead = null;
        if ($concurrentRequest !== null) {
            $concurrentRequest();
        }

        return $authorization;
    }

    public function saveSession(Session $session): void
    {
        $this->inner->saveSession($session);
    }

    public function findSession(string $id): ?Session
    {
        return $this->inner->findSession($id);
    }

    public function signOutSessions(string $accountTokenId): void
    {
        $this->inner->signOutSessions($accountTokenId);
    }

    public function saveAccountToken(AccountToken $token): void
    {
        $this->inner->saveAccountToken($token);
    }

    public function findAccountTokenByHash(string $hash): ?AccountToken
    {
        return $this->inner->findAccountTokenByHash($hash);
    }

    public function findAccountToken(string $id): ?AccountToken
    {
        return $this->inner->findAccountToken($id);
    }

    public function findAccountTokensForAccount(string $accountId): array
    {
        return $this->inner->findAccountTokensForAccount($accountId);
    }

    public function saveSessionToken(SessionToken $token): void
    {
        $this->inner->saveSessionToken($token);
    }

    public function findSessionTokenByHash(string $hash): ?SessionToken
    {
        return $this->inner->findSessionTokenByHash($hash);
    }

    public function saveAuthorizationCode(AuthorizationCode $code): void
    {
        $this->inner->saveAuthorizationCode($code);
    }

    public function consumeAuthorizationCode(string $hash): ?AuthorizationCode
    {
        return $this->inner->consumeAuthorizationCode($hash);
    }

    public function saveDeviceAuthorization(DeviceAuthorization $authorization): void
    {
        $this->inner->saveDeviceAuthorization($authorization);
    }

    public function findDeviceAuthorizationByUserCode(string $userCode): ?DeviceAuthorization
    {
        return $this->inner->findDeviceAuthorizationByUserCode($userCode);
    }

    public function recordDevicePoll(string $deviceCodeHash, \DateTimeImmutable $at, int $interval): void
    {
        $this->inner->recordDevicePoll($deviceCodeHash, $at, $interval);
    }

    public function approveDeviceAuthorization(string $deviceCodeHash, string $accountId, array $grantedScopes): bool
    {
        return $this->inner->approveDeviceAuthorization($deviceCodeHash, $accountId, $grantedScopes);
    }

    public function denyDeviceAuthorization(string $deviceCodeHash): bool
    {
        return $this->inner->denyDeviceAuthorization($deviceCodeHash);
    }

    public function consumeApprovedDeviceAuthorization(string $deviceCodeHash): ?DeviceAuthorization
    {
        return $this->inner->consumeApprovedDeviceAuthorization($deviceCodeHash);
    }

    public function purgeExpired(\DateTimeImmutable $now): void
    {
        $this->inner->purgeExpired($now);
    }
}
