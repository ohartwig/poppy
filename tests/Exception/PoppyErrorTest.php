<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Tests\Exception;

use Koh\Poppy\Exception\PoppyError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The error codes and statuses of Poppy 0.2, 4.2 and section 6, one by one. */
final class PoppyErrorTest extends TestCase
{
    /** @return iterable<int, array{PoppyError, string, int}> */
    public static function errors(): iterable
    {
        yield [PoppyError::invalidRequest('x'), 'invalid_request', 400];
        yield [PoppyError::invalidClient('x'), 'invalid_client', 401];
        yield [PoppyError::invalidGrant('x'), 'invalid_grant', 400];
        yield [PoppyError::invalidScope('x'), 'invalid_scope', 400];
        yield [PoppyError::invalidTarget('x'), 'invalid_target', 400];
        yield [PoppyError::unsupportedGrantType(), 'unsupported_grant_type', 400];
        yield [PoppyError::invalidSession(), 'invalid_session', 400];
        yield [PoppyError::accountMismatch(), 'account_mismatch', 400];
        yield [PoppyError::invalidDpopProof('x'), 'invalid_dpop_proof', 400];
        yield [PoppyError::invalidDpopProof('x', 401), 'invalid_dpop_proof', 401];
        yield [PoppyError::useDpopNonce('n'), 'use_dpop_nonce', 400];
        yield [PoppyError::rateLimited(7), 'rate_limited', 429];
        yield [PoppyError::authorizationPending(), 'authorization_pending', 400];
        yield [PoppyError::slowDown(), 'slow_down', 400];
        yield [PoppyError::accessDenied(), 'access_denied', 400];
        yield [PoppyError::expiredToken(), 'expired_token', 400];
        yield [PoppyError::invalidToken(), 'invalid_token', 401];
        yield [PoppyError::signInRequired(), 'sign_in_required', 403];
        yield [PoppyError::insufficientScope(['poppy:read']), 'insufficient_scope', 403];
    }

    #[DataProvider('errors')]
    public function testCodeAndStatus(PoppyError $error, string $code, int $status): void
    {
        self::assertSame($code, $error->error);
        self::assertSame($status, $error->status);
        self::assertSame($code, $error->body()['error']);
        self::assertNotSame('', $error->body()['error_description']);
    }

    public function testHeadersAndExtraMembers(): void
    {
        self::assertSame(['DPoP-Nonce' => 'n1'], PoppyError::useDpopNonce('n1')->headers);
        self::assertSame(['Retry-After' => '7'], PoppyError::rateLimited(7)->headers);
        self::assertSame(['Retry-After' => '1'], PoppyError::rateLimited(0)->headers, 'never tell a client to retry at once');
        self::assertSame('poppy:read poppy:write', PoppyError::insufficientScope(['poppy:read', 'poppy:write'])->body()['scope']);
        self::assertSame([], PoppyError::invalidGrant('x')->headers);
        self::assertSame('x', PoppyError::invalidGrant('x')->getMessage());
    }
}
