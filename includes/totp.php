<?php
// includes/totp.php
// RFC 6238 TOTP helpers: Base32 decode, HOTP, TOTP generate/verify.
// Works with Google/Microsoft Authenticator (SHA1, 6 digits, 30s).

if (!defined('ABSPATH')) exit;

/**
 * Decode a Base32 string (RFC 4648, no padding required).
 * Returns raw binary string or false on invalid input.
 */
function base32_decode_rfc4648($b32) {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  $b32 = strtoupper(preg_replace('/\s+/', '', (string)$b32));
  $out = '';
  $buffer = 0;
  $bitsLeft = 0;

  $len = strlen($b32);
  for ($i = 0; $i < $len; $i++) {
    $ch = $b32[$i];
    if ($ch === '=') break; // ignore padding
    $val = strpos($alphabet, $ch);
    if ($val === false) return false; // invalid char
    $buffer = ($buffer << 5) | $val;
    $bitsLeft += 5;
    if ($bitsLeft >= 8) {
      $bitsLeft -= 8;
      $out .= chr(($buffer >> $bitsLeft) & 0xFF);
      $buffer &= ((1 << $bitsLeft) - 1);
    }
  }
  // leftover bits must be zero per spec; ignore for compatibility
  return $out;
}

/**
 * HOTP: Truncate dynamic binary code to 6 digits (default).
 */
function hotp($secret_bin, $counter, $digits = 6) {
  // pack counter into 8-byte big-endian
  $ctr = pack('J', 0); // placeholder to ensure 8 bytes on all PHP builds
  // Manual 64-bit big-endian pack for portability
  $ctr = chr(($counter >> 56) & 0xFF) .
         chr(($counter >> 48) & 0xFF) .
         chr(($counter >> 40) & 0xFF) .
         chr(($counter >> 32) & 0xFF) .
         chr(($counter >> 24) & 0xFF) .
         chr(($counter >> 16) & 0xFF) .
         chr(($counter >> 8)  & 0xFF) .
         chr($counter & 0xFF);

  $hmac = hash_hmac('sha1', $ctr, $secret_bin, true); // TOTP default: SHA1
  $offset = ord($hmac[19]) & 0x0F;
  $binCode = ((ord($hmac[$offset]) & 0x7F) << 24) |
             ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
             ((ord($hmac[$offset + 2]) & 0xFF) << 8) |
             (ord($hmac[$offset + 3]) & 0xFF);
  $mod = pow(10, $digits);
  $code = $binCode % $mod;
  return str_pad((string)$code, $digits, '0', STR_PAD_LEFT);
}

/**
 * TOTP current code for a given Base32 secret.
 * @param string $secret_b32 Base32 encoded secret
 * @param int    $time_step  Period in seconds (default 30)
 * @param int    $t0         Unix epoch start (default 0)
 * @param int    $digits     Code length (default 6)
 */
function totp_now($secret_b32, $time_step = 30, $t0 = 0, $digits = 6) {
  $secret_bin = base32_decode_rfc4648($secret_b32);
  if ($secret_bin === false) return false;
  $counter = floor((time() - $t0) / $time_step);
  return hotp($secret_bin, $counter, $digits);
}

/**
 * Verify a user-supplied TOTP code.
 * @param string $secret_b32 Base32 secret
 * @param string $code       User input (e.g., "123456")
 * @param int    $window     Allowed steps of drift on each side (default 1)
 * @param int    $time_step  Period in seconds (default 30)
 * @param int    $t0         Epoch start (default 0)
 * @param int    $digits     Code length (default 6)
 * @return bool
 */
function totp_verify($secret_b32, $code, $window = 1, $time_step = 30, $t0 = 0, $digits = 6) {
  $code = preg_replace('/\D/', '', (string)$code);
  if ($code === '' || strlen($code) !== $digits) return false;

  $secret_bin = base32_decode_rfc4648($secret_b32);
  if ($secret_bin === false) return false;

  $ctr = floor((time() - $t0) / $time_step);

  // constant-time compare helper
  $cteq = function($a, $b) {
    if (function_exists('hash_equals')) return hash_equals($a, $b);
    if (strlen($a) !== strlen($b)) return false;
    $res = 0;
    for ($i=0; $i<strlen($a); $i++) $res |= ord($a[$i]) ^ ord($b[$i]);
    return $res === 0;
  };

  // check current, past, and future windows
  for ($w = -abs((int)$window); $w <= abs((int)$window); $w++) {
    $calc = hotp($secret_bin, $ctr + $w, $digits);
    if ($cteq($calc, $code)) return true;
  }
  return false;
}

/**
 * Build otpauth URI for QR codes.
 * Example label: "{$issuer}:{$accountName}"
 */
function totp_otpauth_uri($account_label, $secret_b32, $issuer, $digits = 6, $period = 30) {
  $label = rawurlencode($account_label);
  $params = http_build_query([
    'secret' => $secret_b32,
    'issuer' => $issuer,
    'digits' => $digits,
    'period' => $period,
    // 'algorithm' => 'SHA1' // default; omit for GA/MSA compatibility
  ]);
  return "otpauth://totp/{$label}?{$params}";
}
