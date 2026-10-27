<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Assertion\BrowserAssertionVerifier;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Server\Model\Session;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;

/**
 * A Personal Agent's browser joining a Session (Poppy 0.2, section 5).
 *
 * join() checks the posted assertion and the Session behind it; the
 * integration then sets its own cookie, links it to the Session id and answers
 * 303 to the returned URL. On every later page request it calls current() with
 * the id from that cookie: the cookie follows the Session's state — signed in,
 * signed out, scopes changed — because the state is read from the Session each
 * time rather than copied into the cookie.
 */
final readonly class BrowserSessions
{
    public function __construct(
        private BrowserAssertionVerifier $assertions,
        private PoppyStorage $storage,
        private ClockInterface $clock,
    ) {}

    /**
     * @return array{Session, string} the Session and the HTTPS URL to send the browser to
     *
     * @throws PoppyError invalid_request; answer it with an error page and HTTP 400, setting no cookie
     */
    public function join(string $assertion): array
    {
        $verified = $this->assertions->verify($assertion);

        $session = $this->storage->findSession($verified->sessionId);
        if ($session === null || !$session->isActive($this->clock->now()) || !$session->belongsTo($verified->clientId, $verified->userId)) {
            throw PoppyError::invalidRequest('The Session is not active or belongs to another Personal Agent or User.');
        }

        return [$session, $verified->returnTo];
    }

    /** The Session behind a browser cookie, while it is active. */
    public function current(string $sessionId): ?Session
    {
        $session = $this->storage->findSession($sessionId);

        return $session !== null && $session->isActive($this->clock->now()) ? $session : null;
    }
}
