# GV Simple 2FA

A hardened Two-Factor Authentication (2FA) solution for WordPress logins, prioritizing security and usability.

TOTP Standard: Works with standard authenticator apps (Google Authenticator, Authy, etc.).

Secure Login Flow: Intercepts login after password validation using a dedicated, transient-protected verification page.

Backup Codes: Provides secure, one-time-use backup codes for recovery.

Signed "Remember Device": Implements a robust, HMAC-signed cookie mechanism for the "Remember Me" feature.

Role Enforcement: Allows administrators to require 2FA for specific user roles.
