<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Assertion;

use Koh\Poppy\Client\AuthenticatedClient;
use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Replay\ReplayGuard;
use Psr\Clock\ClockInterface;

/**
 * The assertion that starts or renews a Session: the JWT bearer grant of
 * RFC 7523 with the claims of Poppy 0.2, 4.2. Its `sub` is the User ID.
 */
final readonly class SessionAssertionVerifier
{
    private const MAX_LIFETIME = 300;

    private const MAX_USER_ID_LENGTH = 255;

    /** @param list<Algorithm> $algorithms */
    public function __construct(
        private string $issuer,
        private ReplayGuard $replayGuard,
        private ClockInterface $clock,
        private array $algorithms = [Algorithm::ES256, Algorithm::ES384, Algorithm::RS256, Algorithm::EdDSA, Algorithm::Ed25519],
    ) {}

    /**
     * @return string the User ID
     *
     * @throws PoppyError invalid_grant
     */
    public function verify(string $assertion, AuthenticatedClient $client): string
    {
        try {
            $jws = Jws::parse($assertion);
        } catch (InvalidJose $exception) {
            throw PoppyError::invalidGrant($exception->getMessage());
        }

        if (in_array($jws->type(), ['poppy-browser+jwt', 'dpop+jwt'], true)) {
            throw PoppyError::invalidGrant('not a Session assertion');
        }

        if ($jws->string('iss') !== $client->clientId()) {
            throw PoppyError::invalidGrant('iss of the assertion must be the authenticated client_id');
        }

        $userId = $jws->string('sub');
        if ($userId === null || strlen($userId) > self::MAX_USER_ID_LENGTH) {
            throw PoppyError::invalidGrant('sub must be the User ID');
        }

        $failure = JwtChecks::audience($jws, $this->issuer)
            ?? JwtChecks::lifetime($jws, $this->clock->now(), self::MAX_LIFETIME)
            ?? JwtChecks::jti($jws)
            ?? JwtChecks::signature($jws, $client->metadata->keys, $this->algorithms);
        if ($failure !== null) {
            throw PoppyError::invalidGrant('assertion: ' . $failure);
        }

        if (!$this->replayGuard->claim('session-assertion:' . $client->clientId(), (string) $jws->string('jti'), JwtChecks::rememberUntil($jws))) {
            throw PoppyError::invalidGrant('assertion was already used');
        }

        return $userId;
    }
}
