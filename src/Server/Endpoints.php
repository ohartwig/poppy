<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Http\Url;

/**
 * The public URLs of the authorization server's endpoints.
 *
 * Kept apart from the issuer because the issuer is an identifier and the
 * endpoints are locations: a deployment may route them anywhere, and only the
 * issuer has to stay byte-for-byte stable.
 */
final readonly class Endpoints
{
    public function __construct(
        public string $token,
        public string $revocation,
        public string $authorization,
        public string $deviceAuthorization,
        public string $deviceVerification,
    ) {
        foreach ([$token, $revocation, $authorization, $deviceAuthorization, $deviceVerification] as $url) {
            if (!Url::isHttps($url)) {
                throw new \InvalidArgumentException('Every endpoint must be an HTTPS URL.');
            }
        }
    }

    /** The default layout: every endpoint below the issuer's path. */
    public static function below(string $issuer): self
    {
        $base = rtrim($issuer, '/');

        return new self($base . '/token', $base . '/revoke', $base . '/authorize', $base . '/device_authorization', $base . '/device');
    }
}
