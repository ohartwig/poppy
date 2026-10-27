<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Dpop;

/** A DPoP proof that passed every check; `jkt` is the thumbprint of the key it was signed with. */
final readonly class DpopProof
{
    public function __construct(
        public string $jkt,
        public string $jti,
    ) {}
}
