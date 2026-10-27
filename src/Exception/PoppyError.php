<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Exception;

/**
 * A protocol error with the code, HTTP status and headers the specification
 * prescribes for it.
 *
 * The description is sent to the Personal Agent. It names the rule that
 * failed and never echoes input: a description that repeats a token, an
 * assertion or a credential would hand it to whoever reads the response or the
 * logs it lands in.
 */
final class PoppyError extends \RuntimeException
{
    /**
     * @param array<string, string> $headers
     * @param array<string, string> $extra   further members of the JSON error body
     */
    private function __construct(
        public readonly string $error,
        public readonly int $status,
        string $description,
        public readonly array $headers = [],
        public readonly array $extra = [],
    ) {
        parent::__construct($description);
    }

    public static function invalidRequest(string $description): self
    {
        return new self('invalid_request', 400, $description);
    }

    public static function invalidClient(string $description): self
    {
        return new self('invalid_client', 401, $description);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', 400, $description);
    }

    public static function invalidScope(string $description): self
    {
        return new self('invalid_scope', 400, $description);
    }

    public static function invalidTarget(string $description): self
    {
        return new self('invalid_target', 400, $description);
    }

    public static function unsupportedGrantType(): self
    {
        return new self('unsupported_grant_type', 400, 'The grant type is not supported.');
    }

    public static function invalidSession(string $description = 'The Session has ended, or belongs to a different Personal Agent or User. Start a new Session.'): self
    {
        return new self('invalid_session', 400, $description);
    }

    public static function accountMismatch(): self
    {
        return new self('account_mismatch', 400, 'The Session is, or was, signed in to a different account. Start a new Session.');
    }

    public static function invalidDpopProof(string $description, int $status = 400): self
    {
        return new self('invalid_dpop_proof', $status, $description);
    }

    public static function useDpopNonce(string $nonce, int $status = 400): self
    {
        return new self('use_dpop_nonce', $status, 'A DPoP nonce is required.', ['DPoP-Nonce' => $nonce]);
    }

    public static function rateLimited(int $retryAfter): self
    {
        return new self('rate_limited', 429, 'Too many requests.', ['Retry-After' => (string) max(1, $retryAfter)]);
    }

    public static function authorizationPending(): self
    {
        return new self('authorization_pending', 400, 'The User has not finished signing in yet.');
    }

    public static function slowDown(): self
    {
        return new self('slow_down', 400, 'Poll less often.');
    }

    public static function accessDenied(): self
    {
        return new self('access_denied', 400, 'The User declined.');
    }

    public static function expiredToken(): self
    {
        return new self('expired_token', 400, 'The device code has expired.');
    }

    public static function invalidToken(string $description = 'The token is missing, expired or not valid here.'): self
    {
        return new self('invalid_token', 401, $description);
    }

    public static function signInRequired(): self
    {
        return new self('sign_in_required', 403, 'This request needs a signed-in Session.');
    }

    /** @param list<string> $scopes */
    public static function insufficientScope(array $scopes): self
    {
        return new self('insufficient_scope', 403, 'The token lacks required scopes.', [], ['scope' => implode(' ', $scopes)]);
    }

    /** @return array<string, string> */
    public function body(): array
    {
        return ['error' => $this->error, 'error_description' => $this->getMessage()] + $this->extra;
    }
}
