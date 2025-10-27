<?php
// includes/class-2fa-admin.php
// Admin settings: enforce roles, window, remember days, lockout attempts.

if (!defined('ABSPATH')) exit;

class GV2FA_Admin {
  const OPT = 'gv2fa_settings';

  public static function init() {
    add_action('admin_init', [__CLASS__, 'register_settings']);
    add_action('admin_menu', [__CLASS__, 'menu']);
  }

  public static function defaults() {
    return [
      'enforce_roles'  => [],   // array of role slugs
      'window'         => 1,    // ± steps
      'remember_days'  => 30,   // cookie days
      'max_attempts'   => 5,    // before temporary lock
      'lock_minutes'   => 10,   // lock duration
      'require_ssl'    => 1,    // refuse without HTTPS
    ];
  }

  public static function get() {
    return wp_parse_args(get_option(self::OPT, []), self::defaults());
  }

  public static function register_settings() {
    register_setting(self::OPT, self::OPT, [__CLASS__, 'sanitize']);

    add_settings_section('gv2fa_main', 'GV 2FA Settings', function(){
      echo '<p>Organization-wide 2FA policy.</p>';
    }, self::OPT);

    add_settings_field('enforce_roles', 'Enforce for roles', [__CLASS__, 'field_roles'], self::OPT, 'gv2fa_main');
    add_settings_field('window', 'Time window (steps)', [__CLASS__, 'field_window'], self::OPT, 'gv2fa_main');
    add_settings_field('remember_days', 'Remember device (days)', [__CLASS__, 'field_remember'], self::OPT, 'gv2fa_main');
    add_settings_field('max_attempts', 'Max attempts', [__CLASS__, 'field_attempts'], self::OPT, 'gv2fa_main');
    add_settings_field('lock_minutes', 'Lockout (minutes)', [__CLASS__, 'field_lock'], self::OPT, 'gv2fa_main');
    add_settings_field('require_ssl', 'Require HTTPS', [__CLASS__, 'field_ssl'], self::OPT, 'gv2fa_main');
  }

  public static function sanitize($in) {
    $d = self::defaults();
    $out = [];
    $out['enforce_roles'] = array_values(array_filter(array_map('sanitize_key', (array)($in['enforce_roles'] ?? []))));
    $out['window']        = max(0, intval($in['window'] ?? $d['window']));
    $out['remember_days'] = max(0, intval($in['remember_days'] ?? $d['remember_days']));
    $out['max_attempts']  = max(1, intval($in['max_attempts'] ?? $d['max_attempts']));
    $out['lock_minutes']  = max(1, intval($in['lock_minutes'] ?? $d['lock_minutes']));
    $out['require_ssl']   = !empty($in['require_ssl']) ? 1 : 0;
    return $out;
  }

  public static function menu() {
    add_options_page('GV 2FA', 'GV 2FA', 'manage_options', self::OPT, [__CLASS__, 'render']);
  }

  public static function render() {
    if (!current_user_can('manage_options')) return;
    ?>
    <div class="wrap">
      <h1>GV 2FA</h1>
      <form method="post" action="options.php">
        <?php
          settings_fields(self::OPT);
          do_settings_sections(self::OPT);
          submit_button('Save settings');
        ?>
      </form>
    </div>
    <?php
  }

  /* ------- Fields ------- */
  public static function field_roles() {
    $opts = self::get();
    global $wp_roles;
    $roles = $wp_roles->roles;
    foreach ($roles as $slug => $role) {
      printf(
        '<label><input type="checkbox" name="%1$s[enforce_roles][]" value="%2$s" %3$s> %4$s</label><br/>',
        esc_attr(self::OPT),
        esc_attr($slug),
        checked(in_array($slug, (array)$opts['enforce_roles'], true), true, false),
        esc_html($role['name'])
      );
    }
    echo '<p class="description">Users in these roles must pass 2FA at login.</p>';
  }

  public static function field_window() {
    $v = self::get()['window'];
    printf('<input type="number" min="0" step="1" name="%s[window]" value="%d" /> <span class="description">± 30s steps allowed (default 1)</span>', esc_attr(self::OPT), intval($v));
  }

  public static function field_remember() {
    $v = self::get()['remember_days'];
    printf('<input type="number" min="0" step="1" name="%s[remember_days]" value="%d" /> <span class="description">0 disables remember-device</span>', esc_attr(self::OPT), intval($v));
  }

  public static function field_attempts() {
    $v = self::get()['max_attempts'];
    printf('<input type="number" min="1" step="1" name="%s[max_attempts]" value="%d" />', esc_attr(self::OPT), intval($v));
  }

  public static function field_lock() {
    $v = self::get()['lock_minutes'];
    printf('<input type="number" min="1" step="1" name="%s[lock_minutes]" value="%d" />', esc_attr(self::OPT), intval($v));
  }

  public static function field_ssl() {
    $v = self::get()['require_ssl'];
    printf('<label><input type="checkbox" name="%s[require_ssl]" value="1" %s> Enforce HTTPS (recommended)</label>', esc_attr(self::OPT), checked($v, 1, false));
  }
}

GV2FA_Admin::init();
