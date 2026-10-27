<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\Poppy\Jose;

/**
 * The few DER constructions needed to hand a JWK to ext-openssl.
 *
 * openssl cannot import a JWK, but it reads a SubjectPublicKeyInfo. Building
 * that structure takes three ASN.1 types, so it is written out here instead of
 * pulling in an ASN.1 library for both frameworks.
 *
 * @internal
 */
final class Der
{
    /** SubjectPublicKeyInfo prefixes up to and including the BIT STRING's unused-bits byte. */
    private const EC_P256_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    private const EC_P384_PREFIX = '3076301006072a8648ce3d020106052b81040022036200';

    private const RSA_ALGORITHM = '300d06092a864886f70d0101010500';

    public static function ecPublicKey(string $curve, string $x, string $y): string
    {
        $prefix = match ($curve) {
            'P-256' => self::EC_P256_PREFIX,
            'P-384' => self::EC_P384_PREFIX,
            default => throw new \InvalidArgumentException('Unsupported curve.'),
        };

        return self::pem(hex2bin($prefix) . "\x04" . $x . $y);
    }

    public static function rsaPublicKey(string $modulus, string $exponent): string
    {
        $key = self::sequence(self::integer($modulus) . self::integer($exponent));

        return self::pem(self::sequence(hex2bin(self::RSA_ALGORITHM) . self::bitString($key)));
    }

    /** JOSE's raw R || S (RFC 7518 §3.4) as the DER ECDSA-Sig-Value openssl expects. */
    public static function ecdsaSignature(string $raw): string
    {
        $half = intdiv(strlen($raw), 2);

        return self::sequence(self::integer(substr($raw, 0, $half)) . self::integer(substr($raw, $half)));
    }

    private static function integer(string $unsigned): string
    {
        $bytes = ltrim($unsigned, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    private static function sequence(string $content): string
    {
        return "\x30" . self::length(strlen($content)) . $content;
    }

    private static function bitString(string $content): string
    {
        return "\x03" . self::length(strlen($content) + 1) . "\x00" . $content;
    }

    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return pack('C', $length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return pack('C', 0x80 | strlen($bytes)) . $bytes;
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }
}
