<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Client;

/**
 * Which Personal Agents a Company accepts (Poppy 0.2, 4.1).
 *
 * Companies MAY require registration, keep allow- and blocklists, and revoke a
 * client_id that misuses the protocol. Any of these answers `invalid_client`.
 * The policy is consulted before anything is fetched from the client_id, so a
 * blocked agent cannot make the server send requests on its behalf.
 */
interface ClientPolicy
{
    public function accepts(string $clientId): bool;
}
