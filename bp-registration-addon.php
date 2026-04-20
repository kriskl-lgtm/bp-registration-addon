<?php
/**
 * Plugin Name: BP Registration Addon
 * Description: Anti-spam addon for BuddyPress registration (honeypot, math captcha, time-trap,
 *              disposable-email blocklist), duplicate email/username checks, blocked usernames,
 *              spaces/length rules, and optional signup nonce protection.
 * Version: 1.4.0
 * Author: Kris
 * Text Domain: bp-registration-addon
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'BPRA_VERSION', '1.4.0' );
define( 'BPRA_PATH', plugin_dir_path( __FILE__ ) );
define( 'BPRA_URL', plugin_dir_url( __FILE__ ) );

// Load all classes — order matters (Logger must be first)
require_once BPRA_PATH . 'includes/class-logger.php';
require_once BPRA_PATH . 'includes/class-settings.php';
require_once BPRA_PATH . 'includes/class-antispam.php';
require_once BPRA_PATH . 'includes/class-banned-domains.php';
require_once BPRA_PATH . 'includes/class-disposable.php';
require_once BPRA_PATH . 'includes/class-ratelimit.php';
require_once BPRA_PATH . 'includes/class-username-rules.php';
require_once BPRA_PATH . 'includes/class-duplicate-check.php';
require_once BPRA_PATH . 'admin/class-admin.php';

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Canonical default values for every setting key the plugin uses.
 * Any key missing from the saved option will fall back to this value.
 */
function bpra_default_settings() {
	return array(
		// Anti-spam
		'enable_honeypot'            => 1,
		'enable_timetrap'            => 1,
		'min_fill_seconds'           => 5,
		'enable_math'                => 0,
		'enable_disposable'          => 1,
		'enable_ratelimit'           => 1,
		'ratelimit_per_hour'         => 5,
		// Username rules
		'enable_username_rules'      => 1,
		'block_numeric_only'         => 1,
		'disallow_username_spaces'   => 1,
		'min_username_length'        => 3,
		'max_username_length'        => 20,
		// Logging
		'log_blocked'                => 1,
		// Domain blocking
		'enable_banned_domains'      => 0,
		'banned_domains'             => '',
		// Username blocking
		'blocked_usernames'          => '',
		'blocked_username_fragments' => '',
		// Signup nonce
		'enable_signup_nonce'        => 0,
	);
}

/**
 * Return saved settings merged with defaults.
 * wp_parse_args fills missing keys without ever overwriting saved values.
 */
function bpra_get_settings() {
	$saved = get_option( 'bpra_settings', array() );
	if ( ! is_array( $saved ) ) {
		$saved = array();
	}
	return wp_parse_args( $saved, bpra_default_settings() );
}

/** Return a single setting value. */
function bpra_setting( $key, $default = null ) {
	$s = bpra_get_settings();
	return array_key_exists( $key, $s ) ? $s[ $key ] : $default;
}

/** Return true when a boolean setting is enabled (non-empty). */
function bpra_is_enabled( $key ) {
	return ! empty( bpra_setting( $key ) );
}

// ─────────────────────────────────────────────────────────────────────────────
// ACTIVATION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * On activation: merge saved settings with defaults.
 * NEVER replaces saved values — only fills in keys that are missing.
 */
function bpra_activate() {
	$current = get_option( 'bpra_settings', array() );
	if ( ! is_array( $current ) ) {
		$current = array();
	}
	update_option( 'bpra_settings', wp_parse_args( $current, bpra_default_settings() ) );

	// username_mode is stored separately so it is not lost on settings reset
	if ( false === get_option( 'bpra_username_mode' ) ) {
		add_option( 'bpra_username_mode', 'letters_numbers' );
	}
}
register_activation_hook( __FILE__, 'bpra_activate' );

// ─────────────────────────────────────────────────────────────────────────────
// BOOTSTRAP
// ─────────────────────────────────────────────────────────────────────────────

function bpra_missing_buddypress_notice() {
	if ( current_user_can( 'activate_plugins' ) ) {
		echo '<div class="notice notice-error"><p>' .
			esc_html__( 'BP Registration Addon requires BuddyPress to be active.', 'bp-registration-addon' ) .
			'</p></div>';
	}
}

/**
 * Boot all components after BuddyPress has loaded.
 * Uses class_exists() guards so a missing/renamed file never causes a fatal.
 * Uses ::instance() for all singleton classes (confirmed from repo source).
 */
function bpra_bootstrap() {
	if ( ! function_exists( 'buddypress' ) ) {
		add_action( 'admin_notices', 'bpra_missing_buddypress_notice' );
		return;
	}

	// Settings — registers bpra_settings with the WP Settings API
	if ( class_exists( 'BPRA_Settings' ) ) {
		BPRA_Settings::instance();
	}

	// Anti-spam: honeypot, timetrap, math captcha
	if ( class_exists( 'BPRA_AntiSpam' ) ) {
		BPRA_AntiSpam::instance();
	}

	// Banned email domains
	if ( class_exists( 'BPRA_BannedDomains' ) ) {
		BPRA_BannedDomains::instance();
	}

	// Disposable email domain blocklist
	if ( class_exists( 'BPRA_Disposable' ) ) {
		BPRA_Disposable::instance();
	}

	// Per-IP rate limiting
	if ( class_exists( 'BPRA_RateLimit' ) ) {
		BPRA_RateLimit::instance();
	}

	// Username character rules, length, spaces, blocked names
	if ( class_exists( 'BPRA_UsernameRules' ) ) {
		BPRA_UsernameRules::instance();
	}

	// Duplicate username/email check (also handles signup nonce)
	if ( class_exists( 'BPRA_DuplicateCheck' ) ) {
		BPRA_DuplicateCheck::instance();
	}

	// Admin settings page
	if ( class_exists( 'BPRA_Admin' ) ) {
		BPRA_Admin::instance();
	}
}
add_action( 'bp_include', 'bpra_bootstrap', 20 );
