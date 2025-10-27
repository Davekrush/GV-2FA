<?php
/*
Plugin Name: GV Simple 2FA
Description: Hardened TOTP 2FA for WordPress. TOTP, backup codes, remember device.
Version: 0.2.0
Author: Gardevault
Author URI: https://gardevault.com
Plugin URI: https://gardevault.com/plugins/gv-simple-2fa
Update URI: false
*/



if (!defined('ABSPATH')) exit;

define('GV2FA_PLUGIN', __FILE__);
define('GV2FA_COOKIE_NAME', 'gv2fa_remember');

// includes
require_once __DIR__ . '/includes/totp.php';
require_once __DIR__ . '/includes/class-2fa-admin.php';
require_once __DIR__ . '/includes/class-2fa-user.php';

/* ----------------------
   Assets
   ---------------------- */
add_action('admin_enqueue_scripts', function () {
  wp_enqueue_style('gv2fa-admin', plugins_url('assets/css/admin.css', GV2FA_PLUGIN), [], '0.2.0');
});
add_action('login_enqueue_scripts', function () {
  // core login styles via login_header(); this adds our small overrides if any
  wp_enqueue_style('gv2fa-login', plugins_url('assets/css/admin.css', GV2FA_PLUGIN), [], '0.2.0');

  // keep theme JS away from login
  wp_dequeue_script('swup');
  wp_dequeue_script('swup-forms');
}, 100);

add_action('gv_core_register_module', function() {
  gv_core_register_module([
    'slug'=>'gv2fa','name'=>'GV Simple 2FA',
    'version'=>defined('GV2FA_VER')?GV2FA_VER:'',
    'settings_url'=>admin_url('options-general.php?page=gv2fa_settings'),
    'panel_cb'=>null,'cap'=>'manage_options',
  ]);
});

/* ----------------------
   Branding (optional)
   ---------------------- */
add_filter('login_headerurl', fn()=> home_url('/'));
add_filter('login_headertext', fn()=> get_bloginfo('name'));

/* ----------------------
   Helpers
   ---------------------- */
function gv2fa_signing_key() {
  if (function_exists('wp_salt')) return wp_salt('auth');
  foreach (['AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'] as $c) {
    if (defined($c) && constant($c)) return constant($c);
  }
  $seed = __FILE__ . PHP_VERSION . (defined('DB_PASSWORD') ? DB_PASSWORD : '') . php_uname();
  return hash('sha256', $seed);
}

function gv2fa_set_remember_cookie($user_id){
  $opts  = GV2FA_Admin::get();
  $days  = max(0, intval($opts['remember_days']));
  if ($days <= 0) return; // feature disabled

  $token = bin2hex(random_bytes(16));
  $exp   = time() + $days * DAY_IN_SECONDS;
  $data  = "{$user_id}:{$token}:{$exp}";
  $sig   = hash_hmac('sha256', $data, gv2fa_signing_key());
  $cookie= base64_encode($data.':'.$sig);

  $opts_cookie = [
    'expires'  => $exp,
    'path'     => (defined('COOKIEPATH') && COOKIEPATH) ? COOKIEPATH : '/',
    'domain'   => defined('COOKIE_DOMAIN') ? COOKIE_DOMAIN : '',
    'secure'   => is_ssl(),
    'httponly' => true,
    'samesite' => 'Lax',
  ];
  setcookie(GV2FA_COOKIE_NAME, $cookie, $opts_cookie);

  $tokens = json_decode(get_user_meta($user_id,'gv_2fa_remember_tokens',true), true) ?: [];
  $tokens[$token] = $exp;
  update_user_meta($user_id,'gv_2fa_remember_tokens', wp_json_encode($tokens));
}

function gv2fa_check_remember_cookie($user_id){
  if (empty($_COOKIE[GV2FA_COOKIE_NAME])) return false;
  $raw = base64_decode($_COOKIE[GV2FA_COOKIE_NAME]);
  if (!$raw) return false;
  $parts = explode(':', $raw, 4);
  if (count($parts) !== 4) return false;
  list($uid,$token,$exp,$sig) = $parts;
  if (intval($uid) !== intval($user_id)) return false;
  $data = "{$uid}:{$token}:{$exp}";
  $expect = hash_hmac('sha256', $data, gv2fa_signing_key());
  if (!hash_equals($expect,$sig)) return false;
  if (time() > intval($exp)) return false;
  $tokens = json_decode(get_user_meta($user_id,'gv_2fa_remember_tokens',true), true) ?: [];
  if (!isset($tokens[$token]) || intval($tokens[$token]) !== intval($exp)) return false;
  return true;
}

function gv2fa_rate_keys($user_id){
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  return ["gv2fa_fail_u{$user_id}_{$ip}", "gv2fa_lock_u{$user_id}_{$ip}"];
}

/* ----------------------
   Login flow
   ---------------------- */

/* Gate after password to a dedicated 2FA page */
add_filter('wp_authenticate_user', function ($user) {
  if (is_wp_error($user)) return $user;

  $user_id = $user->ID;
  $enabled = get_user_meta($user_id, 'gv_2fa_enabled', true);
  $enforce = GV2FA_User::role_enforced($user_id);

  if ($enabled || $enforce) {
    if (gv2fa_check_remember_cookie($user_id)) return $user;

    $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : admin_url();

    // password-proof challenge token (5 min TTL)
    $tok = bin2hex(random_bytes(16));
    set_transient("gv2fa_chal_{$user_id}_{$tok}", 1, 5 * MINUTE_IN_SECONDS);

    wp_clear_auth_cookie();
    $args = [
      'gv_2fa_user' => $user_id,
      'gv2fa_token' => $tok,
      'redirect_to' => $redirect_to,
    ];
    wp_safe_redirect(add_query_arg($args, wp_login_url()));
    exit;
  }
  return $user;
}, 30);

/* Render a proper WP-styled 2FA page */
add_action('login_init', function () {
  if (!isset($_GET['gv_2fa_user'])) return;

  $opts = GV2FA_Admin::get();
  if (!empty($opts['require_ssl']) && !is_ssl()) wp_die('2FA requires HTTPS.', 400);

  nocache_headers();

  $user_id = intval($_GET['gv_2fa_user']);
  $tok     = isset($_GET['gv2fa_token']) ? preg_replace('/[^a-f0-9]/i','',$_GET['gv2fa_token']) : '';
  $user    = get_userdata($user_id);

  if (!$user || !$tok || !get_transient("gv2fa_chal_{$user_id}_{$tok}")) {
    wp_die('2FA session expired. Please sign in again.', 403);
  }

  $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw($_REQUEST['redirect_to']) : admin_url();

if (function_exists('login_header')) {
  login_header(__('Two-factor verification', 'gv2fa'), '', null);
} else {
  wp_admin_css('login', true);
  echo '<div id="login">';
}

?>
<div class="gv2fa-box">
  <h2><?php esc_html_e('Two-factor verification','gv2fa'); ?></h2>
  <p class="message"><?php esc_html_e('Enter the 6-digit code or a backup code.','gv2fa'); ?></p>

  <form id="gv2fa-form" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
    <p>
      <label for="gv2fa_code"><?php esc_html_e('Authentication code', 'gv2fa'); ?></label>
      <input class="input" id="gv2fa_code" type="text" inputmode="text" pattern="[A-Za-z0-9]*" maxlength="16"
             name="gv2fa_code" autocomplete="one-time-code" placeholder="" required />
    </p>
    <p class="forgetmenot">
      <label><input type="checkbox" name="gv2fa_remember" /> <?php
        printf(esc_html__('Remember this device (%d days)', 'gv2fa'), intval($opts['remember_days'])); ?></label>
    </p>
    <?php wp_nonce_field('gv2fa_verify','gv2fa_nonce'); ?>
    <input type="hidden" name="action" value="gv2fa_verify" />
    <input type="hidden" name="user_id" value="<?php echo esc_attr($user_id); ?>" />
    <input type="hidden" name="gv2fa_token" value="<?php echo esc_attr($tok); ?>" />
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
    <p class="submit">
      <button type="submit" class="button button-primary button-large"><?php esc_html_e('Verify', 'gv2fa'); ?></button>
    </p>
  </form>
</div>
<?php

if (function_exists('login_footer')) { login_footer(); } else { echo '</div>'; }
exit;

});

/* Verify handler */
add_action('admin_post_nopriv_gv2fa_verify', function () {
  if (!isset($_POST['gv2fa_nonce']) || !wp_verify_nonce($_POST['gv2fa_nonce'], 'gv2fa_verify')) {
    wp_die('Bad nonce', 403);
  }

  $opts = GV2FA_Admin::get();
  if (!empty($opts['require_ssl']) && !is_ssl()) wp_die('HTTPS required.', 400);

  $user_id  = intval($_POST['user_id'] ?? 0);
  $tok      = isset($_POST['gv2fa_token']) ? preg_replace('/[^a-f0-9]/i','',$_POST['gv2fa_token']) : '';
  $code_raw = (string)($_POST['gv2fa_code'] ?? '');
  $code     = preg_replace('/\s+/', '', $code_raw); // allow spaces in pasted backup
  $remember = !empty($_POST['gv2fa_remember']);
  $redirect = !empty($_POST['redirect_to']) ? esc_url_raw($_POST['redirect_to']) : admin_url();

  if (!$user_id || !$tok || $code === '') wp_die('Missing data', 400);
  if (!get_transient("gv2fa_chal_{$user_id}_{$tok}")) wp_die('2FA session invalid.', 403);
  delete_transient("gv2fa_chal_{$user_id}_{$tok}");

  // rate limit per user+IP
  list($fail_k, $lock_k) = gv2fa_rate_keys($user_id);
  if (get_transient($lock_k)) wp_die('Too many attempts. Try later.', 429);

  $ok = false;

  // 1) TOTP
  $secret = get_user_meta($user_id,'gv_2fa_secret',true);
  $window = max(0, intval($opts['window']));
  if ($secret && ctype_digit($code) && strlen($code) <= 8) {
    $ok = totp_verify($secret, $code, $window);
  }

  // 2) Backup codes (8 hex chars stored in gv_2fa_backup_codes)
  if (!$ok) {
    $codes = json_decode(get_user_meta($user_id,'gv_2fa_backup_codes',true), true) ?: [];
    $lc = strtolower($code);
    foreach ($codes as $i => $b) {
      if (hash_equals($b, $lc)) {
        unset($codes[$i]);
        update_user_meta($user_id,'gv_2fa_backup_codes', wp_json_encode(array_values($codes)));
        $ok = true;
        break;
      }
    }
  }

  if (!$ok) {
    // count failure and maybe lock
    $fails = (int) get_transient($fail_k) + 1;
    set_transient($fail_k, $fails, $opts['lock_minutes'] * MINUTE_IN_SECONDS);
    if ($fails >= (int)$opts['max_attempts']) {
      set_transient($lock_k, 1, $opts['lock_minutes'] * MINUTE_IN_SECONDS);
      delete_transient($fail_k);
    }
    wp_die('Invalid 2FA code', 403);
  }

  // success → clear throttles
  delete_transient($fail_k);
  delete_transient($lock_k);

  if ($remember) gv2fa_set_remember_cookie($user_id);

  $u = get_userdata($user_id);
  if (!$u) wp_die('User not found', 404);

  wp_set_current_user($user_id);
  wp_set_auth_cookie($user_id, false, is_ssl());
  do_action('wp_login', $u->user_login, $u);

  nocache_headers();
  wp_safe_redirect($redirect);
  exit;
});
