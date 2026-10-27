<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

use Koh\Poppy\Assertion\JwtChecks;
use Koh\Poppy\Exception\InvalidClientMetadata;
use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Replay\ReplayGuard;
use Psr\Clock\ClockInterface;

/**
 * Authenticates a Personal Agent at the token, revocation and device
 * authorization endpoints with `private_key_jwt` (RFC 7523 §2.2, Poppy 0.2
 * 4.1).
 *
 * The order matters. Everything that can be checked without the network —
 * parameters, shape, policy — is checked before the client_id is fetched, so a
 * malformed or blocked request never makes this server send one. The `jti` is
 * recorded last, after the signature verified: otherwise anyone could burn an
 * agent's future `jti` values with unsigned garbage.
 */
final readonly class ClientAuthenticator
{
    public const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /** Poppy 0.2, 4.1 gives the client assertion the Session assertion's rules: at most five minutes. */
    private const MAX_LIFETIME = 300;

    /** @param list<Algorithm> $algorithms */
    public function __construct(
        private string $issuer,
        private ClientMetadataResolver $resolver,
        private ClientPolicy $policy,
        private ReplayGuard $replayGuard,
        private ClockInterface $clock,
        private array $algorithms = [Algorithm::ES256, Algorithm::ES384, Algorithm::RS256, Algorithm::EdDSA, Algorithm::Ed25519],
    ) {}

    /**
     * @param array<string, mixed> $parameters the form parameters of the request
     *
     * @throws PoppyError invalid_client
     */
    public function authenticate(array $parameters): AuthenticatedClient
    {
        if (($parameters['client_assertion_type'] ?? null) !== self::ASSERTION_TYPE) {
            throw PoppyError::invalidClient('client_assertion_type must be ' . self::ASSERTION_TYPE);
        }

        $assertion = $parameters['client_assertion'] ?? null;
        if (!is_string($assertion)) {
            throw PoppyError::invalidClient('client_assertion is missing');
        }

        try {
            $jws = Jws::parse($assertion);
        } catch (InvalidJose $exception) {
            throw PoppyError::invalidClient($exception->getMessage());
        }

        $clientId = $jws->string('iss');
        if ($clientId === null || $jws->string('sub') !== $clientId) {
            throw PoppyError::invalidClient('iss and sub of the client assertion must both be the client_id');
        }

        $declared = $parameters['client_id'] ?? null;
        if ($declared !== null && $declared !== $clientId) {
            throw PoppyError::invalidClient('client_id does not match the client assertion');
        }

        // A browser assertion or a DPoP proof is signed with the same keys and
        // must never pass as a client assertion.
        if (in_array($jws->type(), ['poppy-browser+jwt', 'dpop+jwt'], true)) {
            throw PoppyError::invalidClient('not a client assertion');
        }

        $failure = JwtChecks::audience($jws, $this->issuer)
            ?? JwtChecks::lifetime($jws, $this->clock->now(), self::MAX_LIFETIME)
            ?? JwtChecks::jti($jws);
        if ($failure !== null) {
            throw PoppyError::invalidClient('client assertion: ' . $failure);
        }

        if (!$this->policy->accepts($clientId)) {
            throw PoppyError::invalidClient('this Personal Agent is not accepted');
        }

        try {
            $metadata = $this->resolver->resolve($clientId);
        } catch (InvalidClientMetadata $exception) {
            throw PoppyError::invalidClient($exception->getMessage());
        }

        $failure = JwtChecks::signature($jws, $metadata->keys, $this->algorithms);
        if ($failure !== null) {
            throw PoppyError::invalidClient('client assertion: ' . $failure);
        }

        if (!$this->replayGuard->claim('client-assertion:' . $clientId, (string) $jws->string('jti'), JwtChecks::rememberUntil($jws))) {
            throw PoppyError::invalidClient('client assertion was already used');
        }

        return new AuthenticatedClient($metadata);
    }
}
