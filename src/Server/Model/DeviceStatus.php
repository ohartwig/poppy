<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Server\Model;

enum DeviceStatus: string
{
    case Pending = 'pending';
    case Approved = 'approved';
    case Denied = 'denied';
    /** Exchanged for tokens, or ended with account_mismatch: either way it cannot be used again. */
    case Consumed = 'consumed';
}
