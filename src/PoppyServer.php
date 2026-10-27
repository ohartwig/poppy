<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy;

use Koh\Poppy\Assertion\BrowserAssertionVerifier;
use Koh\Poppy\Assertion\SessionAssertionVerifier;
use Koh\Poppy\Client\ClientAuthenticator;
use Koh\Poppy\Client\ClientMetadataResolver;
use Koh\Poppy\Client\ClientPolicy;
use Koh\Poppy\Discovery\AuthorizationServerMetadata;
use Koh\Poppy\Dpop\DpopVerifier;
use Koh\Poppy\Dpop\NonceSource;
use Koh\Poppy\Feedback\FeedbackEndpoint;
use Koh\Poppy\Feedback\FeedbackSink;
use Koh\Poppy\Http\JsonFetcher;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Replay\ReplayGuard;
use Koh\Poppy\Resource\ResourceGuard;
use Koh\Poppy\Server\AccountDisconnector;
use Koh\Poppy\Server\BrowserSessions;
use Koh\Poppy\Server\DeviceAuthorizationEndpoint;
use Koh\Poppy\Server\JsonResponder;
use Koh\Poppy\Server\NoRateLimit;
use Koh\Poppy\Server\RateLimiter;
use Koh\Poppy\Server\RevocationEndpoint;
use Koh\Poppy\Server\ServerConfiguration;
use Koh\Poppy\Server\SignIn\DeviceVerification;
use Koh\Poppy\Server\SignIn\DirectSignIn;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Koh\Poppy\Server\TokenEndpoint;
use Koh\Poppy\Server\TokenIssuer;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Wires one Company's authorization server from its configuration and the
 * integration's ports — storage, replay guard, HTTP fetching, rate limiting.
 *
 * The integrations build exactly one of these per issuer and ask it for the
 * endpoint they are routing to; nothing in here holds request state.
 */
final readonly class PoppyServer
{
    /** Algorithms a Personal Agent may sign client, Session and browser assertions with. */
    public const ASSERTION_ALGORITHMS = [Algorithm::ES256, Algorithm::ES384, Algorithm::RS256, Algorithm::EdDSA, Algorithm::Ed25519];

    private ClientMetadataResolver $resolver;

    private ClientAuthenticator $clients;

    private DpopVerifier $dpop;

    private JsonResponder $responder;

    private TokenIssuer $issuer;

    /** @param list<Algorithm> $dpopAlgorithms */
    public function __construct(
        public ServerConfiguration $configuration,
        private PoppyStorage $storage,
        private ReplayGuard $replayGuard,
        private ClientPolicy $policy,
        JsonFetcher $fetcher,
        private ClockInterface $clock,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory,
        private RateLimiter $rateLimiter = new NoRateLimit(),
        ?NonceSource $nonces = null,
        array $dpopAlgorithms = [Algorithm::ES256, Algorithm::ES384, Algorithm::RS256, Algorithm::EdDSA],
    ) {
        $this->resolver = new ClientMetadataResolver($fetcher);
        $this->clients = new ClientAuthenticator($configuration->issuer, $this->resolver, $policy, $replayGuard, $clock, self::ASSERTION_ALGORITHMS);
        $this->dpop = new DpopVerifier($replayGuard, $clock, $dpopAlgorithms, nonces: $nonces);
        $this->responder = new JsonResponder($responseFactory, $streamFactory);
        $this->issuer = new TokenIssuer($configuration, $storage, $clock);
    }

    /** @return array<string, mixed> */
    public function metadata(): array
    {
        return AuthorizationServerMetadata::build($this->configuration, $this->dpop->algorithmNames(), Algorithm::names(self::ASSERTION_ALGORITHMS));
    }

    public function tokenEndpoint(): TokenEndpoint
    {
        return new TokenEndpoint(
            $this->configuration,
            $this->storage,
            $this->clients,
            new SessionAssertionVerifier($this->configuration->issuer, $this->replayGuard, $this->clock, self::ASSERTION_ALGORITHMS),
            $this->dpop,
            $this->issuer,
            $this->responder,
            $this->clock,
            $this->rateLimiter,
        );
    }

    public function revocationEndpoint(): RevocationEndpoint
    {
        return new RevocationEndpoint($this->storage, $this->clients, $this->disconnector(), $this->responder, $this->rateLimiter);
    }

    public function deviceAuthorizationEndpoint(): DeviceAuthorizationEndpoint
    {
        return new DeviceAuthorizationEndpoint($this->configuration, $this->storage, $this->clients, $this->responder, $this->clock, $this->rateLimiter);
    }

    public function directSignIn(): DirectSignIn
    {
        return new DirectSignIn($this->configuration, $this->storage, $this->resolver, $this->policy, $this->clock);
    }

    public function deviceVerification(): DeviceVerification
    {
        return new DeviceVerification($this->storage, $this->resolver, $this->clock);
    }

    public function resourceGuard(bool $rejectReplayedProofs = false): ResourceGuard
    {
        return new ResourceGuard($this->storage, $this->dpop, $this->clock, $rejectReplayedProofs);
    }

    /** @param string $endpoint the public URL of the browser-session endpoint, which is the assertions' `aud` */
    public function browserSessions(string $endpoint, string $organizationDomain): BrowserSessions
    {
        return new BrowserSessions(
            new BrowserAssertionVerifier($endpoint, $organizationDomain, $this->resolver, $this->policy, $this->replayGuard, $this->clock, self::ASSERTION_ALGORITHMS),
            $this->storage,
            $this->clock,
        );
    }

    public function feedbackEndpoint(string $endpoint, FeedbackSink $sink): FeedbackEndpoint
    {
        return new FeedbackEndpoint($endpoint, $this->resourceGuard(), $sink, $this->responder, $this->clock, $this->dpop->algorithmNames(), $this->rateLimiter);
    }

    public function disconnector(): AccountDisconnector
    {
        return new AccountDisconnector($this->storage, $this->clock);
    }

    /** @return list<string> */
    public function dpopAlgorithms(): array
    {
        return $this->dpop->algorithmNames();
    }
}
