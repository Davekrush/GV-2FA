<?php
/**
 * Uninstall handler for GV Simple 2FA
 * Cleans plugin options and all stored user secrets.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) exit;

// delete plugin options
delete_option('gv2fa_settings');

// delete all usermeta keys related to GV Simple 2FA
global $wpdb;
$keys = [
  'gv2fa_secret',
  'gv2fa_enabled',
  'gv2fa_recovery',
  'gv2fa_last_used',
  'gv2fa_temp'
];

foreach ($keys as $key) {
  $wpdb->query(
    $wpdb->prepare(
      "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
      $key
    )
  );
}

// optional: multisite support
if (is_multisite()) {
  $blogs = $wpdb->get_col("SELECT blog_id FROM $wpdb->blogs");
  foreach ($blogs as $blog_id) {
    switch_to_blog($blog_id);
    delete_option('gv2fa_settings');
    foreach ($keys as $key) {
      $wpdb->query(
        $wpdb->prepare(
          "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s",
          $key
        )
      );
    }
    restore_current_blog();
  }
}
