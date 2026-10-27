<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

enum TokenType: string
{
    case DPoP = 'DPoP';
    case Bearer = 'Bearer';
}
