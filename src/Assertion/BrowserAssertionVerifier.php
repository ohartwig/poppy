<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Assertion;

use Koh\Poppy\Client\ClientMetadataResolver;
use Koh\Poppy\Client\ClientPolicy;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Http\Url;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Replay\ReplayGuard;
use Psr\Clock\ClockInterface;

/**
 * The assertion a Personal Agent's browser posts to join a Session (Poppy 0.2,
 * section 5).
 *
 * It arrives without a client assertion — the browser posts it, not the
 * agent's backend — so the signature against the `iss` client's key set is the
 * only authentication there is. Its own `typ` keeps it from ever being taken
 * for a Session assertion, and `aud` names the browser-session endpoint rather
 * than the issuer, so neither kind is accepted where the other belongs.
 *
 * Whether the Session is active and belongs to this client and User is the
 * caller's check: this class knows assertions, not Sessions.
 */
final readonly class BrowserAssertionVerifier
{
    public const TYPE = 'poppy-browser+jwt';

    private const MAX_LIFETIME = 60;

    /** @param list<Algorithm> $algorithms */
    public function __construct(
        private string $endpoint,
        private string $organizationDomain,
        private ClientMetadataResolver $resolver,
        private ClientPolicy $policy,
        private ReplayGuard $replayGuard,
        private ClockInterface $clock,
        private array $algorithms = [Algorithm::ES256, Algorithm::ES384, Algorithm::RS256, Algorithm::EdDSA, Algorithm::Ed25519],
    ) {}

    /** @throws PoppyError invalid_request; the endpoint answers it with an HTML page and HTTP 400 */
    public function verify(string $assertion): BrowserAssertion
    {
        try {
            $jws = Jws::parse($assertion);
        } catch (InvalidJose $exception) {
            throw PoppyError::invalidRequest($exception->getMessage());
        }

        if ($jws->type() !== self::TYPE) {
            throw PoppyError::invalidRequest('typ must be ' . self::TYPE);
        }

        $clientId = $jws->string('iss');
        $userId = $jws->string('sub');
        $sessionId = $jws->string('session_id');
        $returnTo = $jws->string('return_to');
        if ($clientId === null || $userId === null || $sessionId === null || $returnTo === null) {
            throw PoppyError::invalidRequest('iss, sub, session_id and return_to are required');
        }

        if (!Url::isHttps($returnTo) || !Url::isOnDomain($returnTo, $this->organizationDomain)) {
            throw PoppyError::invalidRequest('return_to must be an HTTPS URL on ' . $this->organizationDomain);
        }

        $failure = JwtChecks::audience($jws, $this->endpoint)
            ?? JwtChecks::lifetime($jws, $this->clock->now(), self::MAX_LIFETIME)
            ?? JwtChecks::jti($jws);
        if ($failure !== null) {
            throw PoppyError::invalidRequest('browser assertion: ' . $failure);
        }

        if (!Url::isHttps($clientId) || !$this->policy->accepts($clientId)) {
            throw PoppyError::invalidRequest('this Personal Agent is not accepted');
        }

        try {
            $metadata = $this->resolver->resolve($clientId);
        } catch (InvalidClientMetadata $exception) {
            throw PoppyError::invalidRequest($exception->getMessage());
        }

        $failure = JwtChecks::signature($jws, $metadata->keys, $this->algorithms);
        if ($failure !== null) {
            throw PoppyError::invalidRequest('browser assertion: ' . $failure);
        }

        if (!$this->replayGuard->claim('browser-assertion:' . $clientId, (string) $jws->string('jti'), JwtChecks::rememberUntil($jws))) {
            throw PoppyError::invalidRequest('browser assertion was already used');
        }

        return new BrowserAssertion($clientId, $userId, $sessionId, $returnTo);
    }
}
