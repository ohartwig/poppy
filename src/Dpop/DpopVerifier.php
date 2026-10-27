<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Dpop;

use Koh\Poppy\Exception\InvalidJose;
use Koh\Poppy\Exception\PoppyError;
use Koh\Poppy\Http\Url;
use Koh\Poppy\Jose\Algorithm;
use Koh\Poppy\Jose\Base64Url;
use Koh\Poppy\Jose\Jwk;
use Koh\Poppy\Jose\Jws;
use Koh\Poppy\Replay\ReplayGuard;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Verifies a DPoP proof as RFC 9449 §4.3 describes, with the choices Poppy 0.2
 * section 4.3 makes: ES256 is always accepted, and the token endpoint rejects a
 * reused `jti` while other endpoints may.
 *
 * The URL the proof must name is passed in rather than read from the request.
 * Behind a TLS-terminating proxy the request knows only its internal URL, and
 * a proof signed for the public one would never match — or, worse, a
 * mis-configured proxy would make proofs for the internal URL acceptable.
 */
final readonly class DpopVerifier
{
    public const TYPE = 'dpop+jwt';

    /** @param list<Algorithm> $algorithms must include ES256 */
    public function __construct(
        private ReplayGuard $replayGuard,
        private ClockInterface $clock,
        private array $algorithms = [Algorithm::ES256],
        private int $window = 60,
        private ?NonceSource $nonces = null,
    ) {
        if (!in_array(Algorithm::ES256, $algorithms, true)) {
            throw new \InvalidArgumentException('Poppy requires ES256 to be accepted for DPoP proofs.');
        }
    }

    /** @return list<string> for `dpop_signing_alg_values_supported` and the `algs` challenge parameter */
    public function algorithmNames(): array
    {
        return Algorithm::names($this->algorithms);
    }

    /**
     * @param string      $htu           the public URL of the endpoint, without query
     * @param string|null $accessToken   the token sent with the proof; its hash must be in `ath`
     * @param string|null $boundJkt      the key the token is bound to
     * @param bool        $rejectReplays true at the token endpoint, where a replay could mint a token
     * @param int         $status        400 at the token endpoint, 401 at resources (Poppy 0.2, 4.3)
     *
     * @throws PoppyError invalid_dpop_proof or use_dpop_nonce
     */
    public function verify(
        ServerRequestInterface $request,
        string $htu,
        ?string $accessToken = null,
        ?string $boundJkt = null,
        bool $rejectReplays = false,
        int $status = 400,
    ): DpopProof {
        $headers = $request->getHeader('DPoP');
        if ($headers === []) {
            throw PoppyError::invalidDpopProof('A DPoP proof is required.', $status);
        }
        if (count($headers) !== 1 || str_contains($headers[0], ',')) {
            throw PoppyError::invalidDpopProof('Exactly one DPoP header is allowed.', $status);
        }

        try {
            $jws = Jws::parse(trim($headers[0]));
        } catch (InvalidJose $exception) {
            throw PoppyError::invalidDpopProof($exception->getMessage(), $status);
        }

        if ($jws->type() !== self::TYPE) {
            throw PoppyError::invalidDpopProof('typ must be ' . self::TYPE, $status);
        }

        $algorithm = $jws->algorithm();
        if ($algorithm === null || !in_array($algorithm, $this->algorithms, true)) {
            throw PoppyError::invalidDpopProof('alg is not accepted', $status);
        }

        $jwk = $jws->header['jwk'] ?? null;
        if (!is_array($jwk)) {
            throw PoppyError::invalidDpopProof('jwk header is required', $status);
        }

        try {
            $key = Jwk::fromArray($jwk);
        } catch (InvalidJose $exception) {
            throw PoppyError::invalidDpopProof($exception->getMessage(), $status);
        }

        if (!$key->verify($algorithm, $jws->signingInput, $jws->signature)) {
            throw PoppyError::invalidDpopProof('signature does not verify with the header key', $status);
        }

        $jti = $jws->string('jti');
        if ($jti === null || strlen($jti) > 256) {
            throw PoppyError::invalidDpopProof('jti is required', $status);
        }

        if ($jws->string('htm') !== $request->getMethod()) {
            throw PoppyError::invalidDpopProof('htm does not match the request method', $status);
        }

        $proofHtu = $jws->string('htu');
        $expected = Url::normalizeForHtu($htu);
        if ($proofHtu === null || $expected === null || Url::normalizeForHtu($proofHtu) !== $expected) {
            throw PoppyError::invalidDpopProof('htu does not match the request URL', $status);
        }

        $issuedAt = $jws->integer('iat');
        $now = $this->clock->now()->getTimestamp();
        if ($issuedAt === null || abs($now - $issuedAt) > $this->window) {
            throw PoppyError::invalidDpopProof('iat is outside the acceptance window', $status);
        }

        if ($this->nonces !== null) {
            $nonce = $jws->string('nonce');
            if ($nonce === null || !$this->nonces->isValid($nonce)) {
                throw PoppyError::useDpopNonce($this->nonces->current(), $status);
            }
        }

        if ($accessToken !== null) {
            $ath = $jws->string('ath');
            if ($ath === null || !hash_equals(Base64Url::encode(hash('sha256', $accessToken, true)), $ath)) {
                throw PoppyError::invalidDpopProof('ath does not match the access token', $status);
            }
        }

        $jkt = $key->thumbprint();
        if ($boundJkt !== null && !hash_equals($boundJkt, $jkt)) {
            throw PoppyError::invalidDpopProof('the proof is not signed with the key the token is bound to', $status);
        }

        if ($rejectReplays && !$this->replayGuard->claim('dpop:' . $jkt, $jti, new \DateTimeImmutable('@' . ($issuedAt + $this->window + 1)))) {
            throw PoppyError::invalidDpopProof('the proof was already used', $status);
        }

        return new DpopProof($jkt, $jti);
    }

    /** A fresh nonce to send in `DPoP-Nonce` on a successful response, when nonces are in use. */
    public function nextNonce(): ?string
    {
        return $this->nonces?->current();
    }
}
