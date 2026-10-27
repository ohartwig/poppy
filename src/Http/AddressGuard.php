<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Http;

/**
 * Decides whether the server may connect to a URL a Personal Agent gave it.
 *
 * Poppy 0.2, section 3: a Company MUST NOT connect to a loopback, private or
 * link-local address for a URL the other party supplied, unless configured to.
 * The client metadata document and the key set behind it are exactly such URLs,
 * and the server fetches them before it knows anything about the caller.
 */
interface AddressGuard
{
    /** @throws \Koh\Poppy\Exception\FetchFailed when the URL must not be fetched */
    public function assertAllowed(string $url): void;
}
