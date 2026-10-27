<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Server\Model\AccountToken;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Model\SessionToken;
use Koh\Poppy\Server\Model\TokenType;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;

/**
 * Creates Sessions, Session Tokens and Account Tokens, and the response
 * bodies that carry them (Poppy 0.2, 4.2 and 4.4).
 *
 * @internal
 */
final readonly class TokenIssuer
{
    public function __construct(
        private ServerConfiguration $configuration,
        private PoppyStorage $storage,
        private ClockInterface $clock,
    ) {}

    public function startSession(string $clientId, string $userId): Session
    {
        $now = $this->clock->now();
        $session = new Session(
            Secrets::id('ses_'),
            $clientId,
            $userId,
            $now,
            $now->modify('+' . $this->configuration->sessionLifetime . ' seconds'),
        );
        $this->storage->saveSession($session);

        return $session;
    }

    /** @param list<string> $scopes */
    public function accountToken(Session $session, string $accountId, array $scopes): IssuedAccountToken
    {
        $now = $this->clock->now();
        $value = Secrets::token('pat_');
        $ttl = $this->configuration->accountTokenTtl;
        $token = new AccountToken(
            Secrets::id('act_'),
            Secrets::hash($value),
            $session->clientId,
            $session->userId,
            $accountId,
            $scopes,
            $now,
            $ttl !== null ? $now->modify('+' . $ttl . ' seconds') : null,
        );
        $this->storage->saveAccountToken($token);

        return new IssuedAccountToken($token, $value);
    }

    /**
     * Issues a Session Token for the Session as it is now, and returns the
     * token response. The Session must already be saved in its current state.
     *
     * @param list<string> $scopes the scopes this token carries, at most the Session's
     *
     * @return array<string, mixed>
     */
    public function sessionTokenResponse(Session $session, TokenType $type, ?string $jkt, ?string $resource, array $scopes, ?IssuedAccountToken $accountToken = null): array
    {
        $now = $this->clock->now();
        $ttl = $this->configuration->sessionTokenTtl;
        $value = Secrets::token('pst_');
        $signedIn = $session->isSignedIn();

        $this->storage->saveSessionToken(new SessionToken(
            Secrets::hash($value),
            $session->id,
            $session->clientId,
            $session->userId,
            $type,
            $type === TokenType::DPoP ? $jkt : null,
            $resource,
            $signedIn ? $scopes : [],
            $session->accountTokenId,
            $now,
            $now->modify('+' . $ttl . ' seconds'),
        ));

        $response = [
            'access_token' => $value,
            'token_type' => $type->value,
            'expires_in' => $ttl,
            'scope' => $signedIn ? Scopes::format($scopes) : '',
            'session_id' => $session->id,
            'signed_in' => $signedIn,
        ];

        if ($accountToken !== null) {
            $response['refresh_token'] = $accountToken->value;
            if ($accountToken->token->expiresAt !== null) {
                $response['refresh_token_expires_in'] = $accountToken->token->expiresAt->getTimestamp() - $now->getTimestamp();
            }
        }

        return $response;
    }
}
