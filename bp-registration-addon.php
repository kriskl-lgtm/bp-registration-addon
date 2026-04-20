<?php
/**
 * Plugin Name: BP Registration Addon
 * Plugin URI:  https://opentuition.com
 * Description: Anti-spam protection for BuddyPress registration forms. Adds honeypot fields, math captcha, time-trap, disposable-email blocklist, banned-domains list, and submission rate-limiting - no third-party services required.
 * Version:     1.1.0
 * Author:      OpenTuition
 * License:     GPL-2.0-or-later
 * Text Domain: bp-registration-addon
 * Requires at least: 5.5
 * Requires PHP: 7.2
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'BPRA_VERSION', '1.1.0' );
define( 'BPRA_FILE', __FILE__ );
define( 'BPRA_DIR', plugin_dir_path( __FILE__ ) );
define( 'BPRA_URL', plugin_dir_url( __FILE__ ) );

/**
 * Activation: seed default options.
 */
register_activation_hook( __FILE__, function () {
    $defaults = array(
        'enable_honeypot'       => 1,
        'enable_timetrap'       => 1,
        'min_fill_seconds'      => 3,
        'enable_math'           => 1,
        'enable_disposable'     => 1,
        'enable_ratelimit'      => 1,
        'ratelimit_per_hour'    => 5,
        'enable_username_rules' => 1,
        'min_username_length'   => 4,
        'block_numeric_only'    => 1,
        'log_blocked'           => 1,
        'enable_banned_domains' => 1,
        'banned_domains'        => '',
    );
    if ( ! get_option( 'bpra_settings' ) ) {
        add_option( 'bpra_settings', $defaults );
    }
});

/**
 * Bootstrap: only run if BuddyPress is active.
 */
add_action( 'bp_include', 'bpra_bootstrap', 20 );
add_action( 'plugins_loaded', 'bpra_maybe_bootstrap_fallback', 20 );

function bpra_maybe_bootstrap_fallback() {
    if ( ! function_exists( 'buddypress' ) ) {
        add_action( 'admin_notices', function () {
            if ( ! current_user_can( 'manage_options' ) ) return;
            echo '<div class="notice notice-warning"><p><strong>BP Registration Addon:</strong> BuddyPress is not active. This addon only works when BuddyPress is installed and active.</p></div>';
        });
    }
}

function bpra_bootstrap() {
    require_once BPRA_DIR . 'includes/class-settings.php';
    require_once BPRA_DIR . 'includes/class-logger.php';
    require_once BPRA_DIR . 'includes/class-antispam.php';
    require_once BPRA_DIR . 'includes/class-disposable.php';
    require_once BPRA_DIR . 'includes/class-banned-domains.php';
    require_once BPRA_DIR . 'includes/class-ratelimit.php';
    require_once BPRA_DIR . 'includes/class-username-rules.php';

    BPRA_Settings::instance();
    BPRA_Logger::instance();
    BPRA_AntiSpam::instance();
    BPRA_Disposable::instance();
    BPRA_BannedDomains::instance();
    BPRA_RateLimit::instance();
    BPRA_UsernameRules::instance();

    if ( is_admin() ) {
        require_once BPRA_DIR . 'admin/class-admin.php';
        BPRA_Admin::instance();
    }
}

/**
 * Helper: get settings array with defaults merged.
 */
function bpra_get_settings() {
    $defaults = array(
        'enable_honeypot'       => 1,
        'enable_timetrap'       => 1,
        'min_fill_seconds'      => 3,
        'enable_math'           => 1,
        'enable_disposable'     => 1,
        'enable_ratelimit'      => 1,
        'ratelimit_per_hour'    => 5,
        'enable_username_rules' => 1,
        'min_username_length'   => 4,
        'block_numeric_only'    => 1,
        'log_blocked'           => 1,
        'enable_banned_domains' => 1,
        'banned_domains'        => '',
    );
    $saved = get_option( 'bpra_settings', array() );
    return wp_parse_args( is_array( $saved ) ? $saved : array(), $defaults );
}

function bpra_is_enabled( $key ) {
    $s = bpra_get_settings();
    return ! empty( $s[ $key ] );
}

function bpra_setting( $key, $default = '' ) {
    $s = bpra_get_settings();
    return isset( $s[ $key ] ) ? $s[ $key ] : $default;
}
