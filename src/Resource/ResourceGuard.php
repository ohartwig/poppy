<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Resource;

use Koh\Poppy\Dpop\DpopVerifier;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Server\Model\TokenType;
use Koh\Poppy\Server\Secrets;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Accepts Session Tokens at an API, a feedback endpoint or an MCP server
 * (Poppy 0.2, 4.3 and section 6).
 *
 * The rules, as the specification states them:
 *
 * - The token is read from the Authorization header only; never from a URL,
 *   never from a cookie.
 * - A DPoP token needs the DPoP scheme and a proof signed with its key; sent
 *   with the Bearer scheme it is refused (RFC 9449 §7.1).
 * - A Bearer token is valid at exactly one MCP server, the one whose URL is
 *   its resource, and refused everywhere else, other paths on the same host
 *   included.
 * - A token issued for a resource is valid only there, and a service that has
 *   a resource accepts only tokens issued for it.
 * - Sign-in is read from the Session on every request: after a sign-out the
 *   request is handled as signed out at once, even with a token issued while
 *   signed in (4.9).
 */
final readonly class ResourceGuard
{
    public function __construct(
        private PoppyStorage $storage,
        private DpopVerifier $dpop,
        private ClockInterface $clock,
        private bool $rejectReplayedProofs = false,
    ) {}

    /**
     * @param string      $htu      the public URL of this request, without query
     * @param string|null $resource the resource identifier of this service; for an MCP server its URL
     * @param bool        $mcp      whether this service is an MCP server, the only place Bearer tokens are valid
     *
     * @throws PoppyError invalid_token, invalid_dpop_proof or use_dpop_nonce, all with HTTP 401
     */
    public function authenticate(ServerRequestInterface $request, string $htu, ?string $resource = null, bool $mcp = false): SessionContext
    {
        $headers = $request->getHeader('Authorization');
        if (count($headers) !== 1 || preg_match('/^(DPoP|Bearer) ([A-Za-z0-9\-._~+\/]+=*)$/D', trim($headers[0]), $match) !== 1) {
            throw PoppyError::invalidToken('A Session Token is required in the Authorization header.');
        }
        [, $scheme, $value] = $match;

        $token = $this->storage->findSessionTokenByHash(Secrets::hash($value));
        $now = $this->clock->now();
        if ($token === null || $token->isExpired($now)) {
            throw PoppyError::invalidToken();
        }

        if ($token->type === TokenType::Bearer) {
            if ($scheme !== 'Bearer' || !$mcp || $resource === null || $token->resource !== $resource) {
                throw PoppyError::invalidToken('This Bearer token is valid only at the MCP server it was issued for.');
            }
        } else {
            if ($scheme !== 'DPoP') {
                throw PoppyError::invalidToken('A DPoP-bound token must be sent with the DPoP scheme.');
            }
            if ($token->resource !== $resource) {
                throw PoppyError::invalidToken('The token was issued for another resource.');
            }
            $this->dpop->verify($request, $htu, $value, $token->jkt, $this->rejectReplayedProofs, 401);
        }

        $session = $this->storage->findSession($token->sessionId);
        if ($session === null || !$session->isActive($now)) {
            throw PoppyError::invalidToken('The Session has ended.');
        }

        $signedIn = $token->accountTokenId !== null && $session->accountTokenId === $token->accountTokenId;
        if ($signedIn) {
            $accountToken = $this->storage->findAccountToken((string) $token->accountTokenId);
            $signedIn = $accountToken !== null && $accountToken->isUsable($now);
        }

        return new SessionContext(
            $session->id,
            $session->clientId,
            $session->userId,
            $signedIn ? $session->accountId : null,
            $signedIn ? $token->scopes : [],
        );
    }
}
