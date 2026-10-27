<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Exception;

/** A document from a Personal Agent could not be fetched, or must not be. */
final class FetchFailed extends \RuntimeException
{
    public static function notHttps(): self
    {
        return new self('Only HTTPS URLs are fetched.');
    }

    public static function forbiddenAddress(): self
    {
        return new self('The URL resolves to an address that is not public, or uses a non-default port.');
    }

    public static function unresolvable(): self
    {
        return new self('The host does not resolve.');
    }

    public static function status(int $status): self
    {
        return new self(sprintf('Unexpected HTTP status %d (redirects are not followed).', $status));
    }

    public static function tooLarge(): self
    {
        return new self('The document exceeds the size limit.');
    }

    public static function notJson(): self
    {
        return new self('The document is not a JSON object.');
    }

    public static function transport(\Throwable $previous): self
    {
        return new self('The request failed.', 0, $previous);
    }
}
