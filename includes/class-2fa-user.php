<?php
// includes/class-2fa-user.php
// User profile UI, enable/disable, backup codes regen, helpers.

if (!defined('ABSPATH')) exit;

require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/class-2fa-admin.php';

class GV2FA_User {
  public static function init() {
    add_action('show_user_profile', [__CLASS__, 'profile_ui']);
    add_action('edit_user_profile', [__CLASS__, 'profile_ui']);
    add_action('personal_options_update', [__CLASS__, 'save_profile']);
    add_action('edit_user_profile_update', [__CLASS__, 'save_profile']);

    add_action('wp_ajax_gv2fa_regen_backup', [__CLASS__, 'ajax_regen_backup']);
    add_action('wp_ajax_gv2fa_disable', [__CLASS__, 'ajax_disable_2fa']);
  }

  public static function profile_ui($user) {
    $enabled = get_user_meta($user->ID, 'gv_2fa_enabled', true);
    $secret  = get_user_meta($user->ID, 'gv_2fa_secret', true);
    if (!$secret) {
      $secret = self::create_secret();
      update_user_meta($user->ID, 'gv_2fa_secret', $secret);
      update_user_meta($user->ID, 'gv_2fa_backup_codes', wp_json_encode(self::generate_backup_codes()));
    }
    $codes  = json_decode(get_user_meta($user->ID, 'gv_2fa_backup_codes', true), true) ?: [];
    $issuer = get_bloginfo('name');
    $label  = $issuer . ':' . $user->user_email;
    $uri    = totp_otpauth_uri($label, $secret, $issuer); // RFC6238 otpauth
    list($qr1, $qr2, $uri_human) = self::qr_urls($uri);   // fallback + readable

    ?>
    <h2>GV 2FA</h2>
    <table class="form-table" role="presentation">
      <tr>
        <th><label>Two-factor status</label></th>
        <td>
          <label>
            <input type="checkbox" name="gv_2fa_enabled" value="1" <?php checked($enabled, '1'); ?> />
            Enable 2FA for this account
          </label>
          <?php wp_nonce_field('gv2fa_profile_save', 'gv2fa_nonce'); ?>
          <p class="description">Scan the QR with Google/Microsoft Authenticator. Enter a code once, then save.</p>
        </td>
      </tr>
      <tr>
        <th><label>Authenticator setup</label></th>
        <td>
          <img src="<?php echo esc_url($qr1); ?>" alt="QR"
               onerror="this.onerror=null;this.src='<?php echo esc_js($qr2); ?>';" /><br/>
          Secret: <code><?php echo esc_html($secret); ?></code><br/>
          URI: <code style="word-break:break-all"><?php echo esc_html($uri_human); ?></code>
        </td>
      </tr>
      <tr>
        <th><label>Backup codes</label></th>
        <td>
          <pre><?php echo esc_html(implode("\n", $codes)); ?></pre>
          <button type="button" class="button" id="gv2fa-regen">Regenerate backup codes</button>
          <p class="description">Store safely. Each code works once.</p>
        </td>
      </tr>
      <?php if ($enabled): ?>
      <tr>
        <th><label>Disable 2FA</label></th>
        <td>
          <button type="button" class="button button-secondary" id="gv2fa-disable">Disable 2FA</button>
        </td>
      </tr>
      <?php endif; ?>
    </table>
    <script>
      (function(){
        const ajax = (action, body) => fetch(ajaxurl, {
          method:'POST',
          headers:{'Content-Type':'application/x-www-form-urlencoded'},
          body: new URLSearchParams(Object.assign({action}, body))
        }).then(r=>r.json());
        const n = "<?php echo wp_create_nonce('gv2fa_ajax'); ?>";
        const uid = "<?php echo intval($user->ID); ?>";

        const regen = document.getElementById('gv2fa-regen');
        if (regen) regen.onclick = async function(){
          const res = await ajax('gv2fa_regen_backup', { _ajax_nonce:n, user_id:uid });
          if (res && res.ok) location.reload();
          else alert(res && res.msg ? res.msg : 'Error');
        };

        const disable = document.getElementById('gv2fa-disable');
        if (disable) disable.onclick = async function(){
          if (!confirm('Disable 2FA for this user?')) return;
          const res = await ajax('gv2fa_disable', { _ajax_nonce:n, user_id:uid });
          if (res && res.ok) location.reload();
          else alert(res && res.msg ? res.msg : 'Error');
        };
      })();
    </script>
    <?php
  }

  public static function save_profile($user_id) {
    if (!current_user_can('edit_user', $user_id)) return;
    if (!isset($_POST['gv2fa_nonce']) || !wp_verify_nonce($_POST['gv2fa_nonce'], 'gv2fa_profile_save')) return;

    $enabled = !empty($_POST['gv_2fa_enabled']) ? '1' : '0';
    update_user_meta($user_id, 'gv_2fa_enabled', $enabled);
  }

  public static function ajax_regen_backup() {
    if (!check_ajax_referer('gv2fa_ajax', false, false)) wp_send_json(['ok'=>false,'msg'=>'Bad nonce'], 403);
    $uid = intval($_POST['user_id'] ?? 0);
    if (!$uid || !current_user_can('edit_user', $uid)) wp_send_json(['ok'=>false,'msg'=>'No capability'], 403);

    update_user_meta($uid, 'gv_2fa_backup_codes', wp_json_encode(self::generate_backup_codes()));
    wp_send_json(['ok'=>true]);
  }

  public static function ajax_disable_2fa() {
    if (!check_ajax_referer('gv2fa_ajax', false, false)) wp_send_json(['ok'=>false,'msg'=>'Bad nonce'], 403);
    $uid = intval($_POST['user_id'] ?? 0);
    if (!$uid || !current_user_can('edit_user', $uid)) wp_send_json(['ok'=>false,'msg'=>'No capability'], 403);

    update_user_meta($uid, 'gv_2fa_enabled', '0');
    wp_send_json(['ok'=>true]);
  }

  /* ------- Helpers ------- */
  public static function create_secret($len = 16) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = '';
    for ($i=0;$i<$len;$i++) $s .= $chars[random_int(0,31)];
    return $s;
  }

  public static function generate_backup_codes($n=10) {
    $out = [];
    for ($i=0;$i<$n;$i++) $out[] = bin2hex(random_bytes(4));
    return $out;
  }

  /** Build QR URLs with fallback and a readable otpauth string. */
  private static function qr_urls($otpauth_uri) {
    $enc = rawurlencode($otpauth_uri);
    $google = "https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl={$enc}";
    $qrsvr  = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={$enc}";
    return [$google, $qrsvr, $otpauth_uri];
  }

  /** Whether the given user must use 2FA due to role enforcement. */
  public static function role_enforced($user_id) {
    $opts = GV2FA_Admin::get();
    $u = get_userdata($user_id);
    if (!$u) return false;
    foreach ((array)$u->roles as $r) {
      if (in_array($r, (array)$opts['enforce_roles'], true)) return true;
    }
    return false;
  }
}

GV2FA_User::init();
