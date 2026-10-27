<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\SignIn;

use Koh\Poppy\Client\ClientMetadata;
use Koh\Poppy\Client\ClientMetadataResolver;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Server\Model\DeviceAuthorization;
use Koh\Poppy\Server\Model\DeviceStatus;
use Koh\Poppy\Server\Secrets;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;

/**
 * The page side of Device Sign-In (RFC 8628 §3.3, Poppy 0.2 4.6).
 *
 * The User enters, or arrives with, a user code, signs in, sees which
 * Personal Agent asks for which scopes, and approves or declines. find() is
 * the step that guesses go through; the integration must rate-limit it per
 * client address, because the code space is small enough to search.
 */
final readonly class DeviceVerification
{
    public function __construct(
        private PoppyStorage $storage,
        private ClientMetadataResolver $resolver,
        private ClockInterface $clock,
    ) {}

    /** @return array{DeviceAuthorization, ClientMetadata}|null a pending authorization and the agent asking, or null */
    public function find(string $userCode): ?array
    {
        $normalized = Secrets::normalizeUserCode($userCode);
        if ($normalized === null) {
            return null;
        }

        $authorization = $this->storage->findDeviceAuthorizationByUserCode($normalized);
        if ($authorization === null || $authorization->status !== DeviceStatus::Pending || $authorization->isExpired($this->clock->now())) {
            return null;
        }

        try {
            return [$authorization, $this->resolver->resolve($authorization->clientId)];
        } catch (InvalidClientMetadata) {
            return null;
        }
    }

    /**
     * @param list<string> $approvedScopes a non-empty subset of the requested scopes; empty declines
     */
    public function approve(DeviceAuthorization $authorization, string $accountId, array $approvedScopes): void
    {
        $scopes = array_values(array_intersect($authorization->requestedScopes, $approvedScopes));
        if ($scopes === []) {
            $this->deny($authorization);

            return;
        }

        $this->storage->saveDeviceAuthorization($authorization->approve($accountId, $scopes));
    }

    public function deny(DeviceAuthorization $authorization): void
    {
        $this->storage->saveDeviceAuthorization($authorization->withStatus(DeviceStatus::Denied));
    }
}
