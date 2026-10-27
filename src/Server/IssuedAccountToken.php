<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server;

use Koh\Poppy\Server\Model\AccountToken;

/**
 * A freshly issued Account Token: the stored record and, for this one
 * response, the token value itself.
 *
 * @internal
 */
final readonly class IssuedAccountToken
{
    public function __construct(
        public AccountToken $token,
        #[\SensitiveParameter]
        public string $value,
    ) {}
}
