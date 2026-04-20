<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers bpra_settings with the WP Settings API and sanitises every key.
 *
 * KEY RULE: every key in bpra_default_settings() MUST appear in sanitize()
 * or it will be stripped the moment the user clicks Save in the admin screen.
 */
class BPRA_Settings {

	private static $instance = null;
	const OPTION = 'bpra_settings';

	public static function instance() {
		if ( self::$instance === null ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_init', array( $this, 'register' ) );
	}

	public function register() {
		register_setting(
			'bpra_group',
			self::OPTION,
			array( $this, 'sanitize' )
		);
		register_setting(
			'bpra_group',
			'bpra_username_mode',
			array( $this, 'sanitize_username_mode' )
		);
	}

	public function sanitize_username_mode( $value ) {
		$allowed = array(
			'letters_numbers',
			'letters_numbers_dot',
			'letters_numbers_dot_dash',
			'wordpress_default',
		);
		return in_array( $value, $allowed, true ) ? $value : 'letters_numbers';
	}

	/**
	 * Sanitise every key from bpra_default_settings().
	 * Missing a key here = that key gets deleted from the DB on every save.
	 */
	public function sanitize( $input ) {
		if ( ! is_array( $input ) ) {
			$input = array();
		}

		$out = array();

		// ── Boolean / checkbox fields ────────────────────────────────────────
		$booleans = array(
			'enable_honeypot',
			'enable_timetrap',
			'enable_math',
			'enable_disposable',
			'enable_ratelimit',
			'enable_username_rules',
			'block_numeric_only',
			'disallow_username_spaces',
			'log_blocked',
			'enable_banned_domains',
			'enable_signup_nonce',
		);
		foreach ( $booleans as $k ) {
			$out[ $k ] = ! empty( $input[ $k ] ) ? 1 : 0;
		}

		// ── Integer fields ───────────────────────────────────────────────────
		$out['min_fill_seconds']   = isset( $input['min_fill_seconds'] )   ? max( 0, (int) $input['min_fill_seconds'] )   : 5;
		$out['ratelimit_per_hour'] = isset( $input['ratelimit_per_hour'] ) ? max( 0, (int) $input['ratelimit_per_hour'] ) : 5;
		$out['min_username_length'] = isset( $input['min_username_length'] ) ? max( 1, (int) $input['min_username_length'] ) : 3;
		$out['max_username_length'] = isset( $input['max_username_length'] ) ? max( 1, (int) $input['max_username_length'] ) : 20;

		// Ensure max >= min
		if ( $out['max_username_length'] < $out['min_username_length'] ) {
			$out['max_username_length'] = $out['min_username_length'];
		}

		// ── Banned domains textarea ──────────────────────────────────────────
		$raw   = isset( $input['banned_domains'] ) ? (string) $input['banned_domains'] : '';
		$lines = preg_split( '/[\r\n,]+/', $raw );
		$clean = array();
		foreach ( $lines as $line ) {
			$d = strtolower( trim( $line ) );
			if ( $d === '' ) {
				continue;
			}
			$d = preg_replace( '#^https?://#', '', $d );
			if ( strpos( $d, '@' ) !== false ) {
				$d = substr( $d, strpos( $d, '@' ) + 1 );
			}
			$d = trim( $d, "/ \t" );
			if ( preg_match( '/^\.?[a-z0-9][a-z0-9\.-]*\.[a-z]{2,}$/', $d ) ) {
				$clean[] = $d;
			}
		}
		$out['banned_domains'] = implode( "\n", array_values( array_unique( $clean ) ) );

		// ── Blocked usernames textarea (exact match) ─────────────────────────
		$raw_u  = isset( $input['blocked_usernames'] ) ? (string) $input['blocked_usernames'] : '';
		$u_lines = preg_split( '/[\r\n]+/', $raw_u );
		$u_clean = array();
		foreach ( $u_lines as $line ) {
			$u = strtolower( sanitize_user( trim( $line ) ) );
			if ( $u !== '' ) {
				$u_clean[] = $u;
			}
		}
		$out['blocked_usernames'] = implode( "\n", array_values( array_unique( $u_clean ) ) );

		// ── Blocked username fragments textarea ──────────────────────────────
		$raw_f   = isset( $input['blocked_username_fragments'] ) ? (string) $input['blocked_username_fragments'] : '';
		$f_lines = preg_split( '/[\r\n]+/', $raw_f );
		$f_clean = array();
		foreach ( $f_lines as $line ) {
			$f = strtolower( sanitize_text_field( trim( $line ) ) );
			if ( $f !== '' ) {
				$f_clean[] = $f;
			}
		}
		$out['blocked_username_fragments'] = implode( "\n", array_values( array_unique( $f_clean ) ) );

		return $out;
	}
}
