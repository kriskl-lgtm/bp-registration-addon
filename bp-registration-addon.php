<?php
/**
 * Plugin Name: BP Registration Addon
 * Description: Anti-spam addon for BuddyPress registration (honeypot, math captcha, time-trap, disposable-email blocklist), duplicate email/username checks, blocked usernames, and optional signup nonce protection.
 * Version: 1.3.0
 * Author: Kris
 * Text Domain: bp-registration-addon
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'BPRA_VERSION', '1.3.0' );
define( 'BPRA_PATH', plugin_dir_path( __FILE__ ) );
define( 'BPRA_URL', plugin_dir_url( __FILE__ ) );

require_once BPRA_PATH . 'includes/class-logger.php';
require_once BPRA_PATH . 'includes/class-settings.php';
require_once BPRA_PATH . 'includes/class-antispam.php';
require_once BPRA_PATH . 'includes/class-banned-domains.php';
require_once BPRA_PATH . 'includes/class-disposable.php';
require_once BPRA_PATH . 'includes/class-ratelimit.php';
require_once BPRA_PATH . 'includes/class-username-rules.php';
require_once BPRA_PATH . 'includes/class-duplicate-check.php';
require_once BPRA_PATH . 'admin/class-admin.php';

/**
 * Default plugin settings.
 */
function bpra_default_settings() {
	return array(
		'enable_honeypot'             => 1,
		'enable_timetrap'             => 1,
		'min_fill_seconds'            => 5,
		'enable_math'                 => 0,
		'enable_disposable'           => 1,
		'enable_ratelimit'            => 1,
		'ratelimit_per_hour'          => 5,
		'enable_username_rules'       => 1,
		'block_numeric_only'          => 1,
		'disallow_username_spaces'    => 1,
		'min_username_length'         => 3,
		'max_username_length'         => 20,
		'log_blocked'                 => 1,
		'enable_banned_domains'       => 0,
		'banned_domains'              => '',
		'blocked_usernames'           => '',
		'blocked_username_fragments'  => '',
		'enable_signup_nonce'         => 0,
	);
}

/**
 * Get merged settings.
 */
function bpra_get_settings() {
	$saved = get_option( 'bpra_settings', array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}

	return wp_parse_args( $saved, bpra_default_settings() );
}

/**
 * Convenience helper.
 */
function bpra_setting( $key, $default = null ) {
	$settings = bpra_get_settings();

	if ( array_key_exists( $key, $settings ) ) {
		return $settings[ $key ];
	}

	return $default;
}

/**
 * Convenience helper.
 */
function bpra_is_enabled( $key ) {
	return ! empty( bpra_setting( $key ) );
}

/**
 * Activation hook: merge defaults, never overwrite saved settings.
 */
function bpra_activate() {
	$current = get_option( 'bpra_settings', array() );
	if ( ! is_array( $current ) ) {
		$current = array();
	}

	$merged = wp_parse_args( $current, bpra_default_settings() );
	update_option( 'bpra_settings', $merged );

	if ( get_option( 'bpra_username_mode', false ) === false ) {
		add_option( 'bpra_username_mode', 'letters_numbers' );
	}
}
register_activation_hook( __FILE__, 'bpra_activate' );

/**
 * Admin notice if BuddyPress is missing.
 */
function bpra_missing_buddypress_notice() {
	if ( current_user_can( 'activate_plugins' ) ) {
		echo '<div class="notice notice-error"><p>' .
			esc_html__( 'BP Registration Addon requires BuddyPress to be active.', 'bp-registration-addon' ) .
		'</p></div>';
	}
}

/**
 * Boot plugin after BuddyPress is loaded.
 */
function bpra_bootstrap() {
	if ( ! function_exists( 'buddypress' ) ) {
		add_action( 'admin_notices', 'bpra_missing_buddypress_notice' );
		return;
	}

	BPRA_Settings::instance();
	BPRA_AntiSpam::instance();
	BPRA_Banned_Domains::instance();
	BPRA_Disposable::instance();
	BPRA_RateLimit::instance();
	BPRA_Username_Rules::instance();
	BPRA_DuplicateCheck::instance();
	BPRA_Admin::instance();
}
add_action( 'bp_include', 'bpra_bootstrap', 20 );
