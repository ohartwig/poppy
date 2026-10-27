<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Client\ClientAuthenticator;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Server\Storage\PoppyStorage;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Sign-out: revokes an Account Token (RFC 7009, Poppy 0.2 4.9).
 *
 * Every Session signed in under the token is signed out and continues signed
 * out. RFC 7009 §2.2 answers 200 for an unknown token as well, so a revocation
 * request reveals nothing about which tokens exist; a token that belongs to
 * another Personal Agent is treated as unknown for the same reason.
 */
final readonly class RevocationEndpoint
{
    public function __construct(
        private PoppyStorage $storage,
        private ClientAuthenticator $clients,
        private AccountDisconnector $disconnector,
        private JsonResponder $responder,
        private RateLimiter $rateLimiter = new NoRateLimit(),
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw PoppyError::invalidRequest('The revocation endpoint accepts POST only.');
            }

            $parameters = FormParameters::from($request);

            $retryAfter = $this->rateLimiter->hit('revoke', $parameters['client_id'] ?? 'unidentified');
            if ($retryAfter !== null) {
                throw PoppyError::rateLimited($retryAfter);
            }

            $client = $this->clients->authenticate($parameters);

            $value = $parameters['token'] ?? null;
            if ($value === null || $value === '') {
                throw PoppyError::invalidRequest('token is required');
            }

            $token = $this->storage->findAccountTokenByHash(Secrets::hash($value));
            if ($token !== null && hash_equals($token->clientId, $client->clientId()) && $token->revokedAt === null) {
                $this->disconnector->revoke($token);
            }
        } catch (PoppyError $error) {
            return $this->responder->error($error);
        }

        return $this->responder->empty(200);
    }
}
