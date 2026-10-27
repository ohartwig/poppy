<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\SignIn;

/**
 * A Direct Sign-In request that cannot proceed.
 *
 * RFC 6749 §4.1.2.1 draws the line: while the client or its redirect URI is
 * in doubt, the error is shown to the User and nothing is redirected — a
 * redirect to an unverified URI would make this server an open redirector.
 * Once both are verified, the error goes back to the Personal Agent as a
 * redirect, carrying `iss` like every response (RFC 9207).
 */
final class AuthorizationError extends \RuntimeException
{
    private function __construct(
        public readonly string $error,
        string $description,
        public readonly ?string $redirectUrl,
    ) {
        parent::__construct($description);
    }

    public static function shown(string $description): self
    {
        return new self('invalid_request', $description, null);
    }

    public static function redirected(string $error, string $description, string $redirectUrl): self
    {
        return new self($error, $description, $redirectUrl);
    }

    public function isRedirect(): bool
    {
        return $this->redirectUrl !== null;
    }
}
