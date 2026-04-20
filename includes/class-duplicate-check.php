<?php
/**
 * Duplicate email checks + configurable username rules for BuddyPress registration.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class BPRA_Duplicate_Check {
	const OPTION_USERNAME_MODE = 'bpra_username_mode';

	public static function init() {
		add_filter( 'wpmu_validate_user_signup', array( __CLASS__, 'check_email_already_registered' ), 20 );
		add_filter( 'validate_username', array( __CLASS__, 'restrict_username_characters' ), 10, 2 );
		add_filter( 'gettext', array( __CLASS__, 'username_error_message' ), 20, 3 );
		add_filter( 'registration_errors', array( __CLASS__, 'username_registration_errors' ), 20, 3 );
		add_filter( 'bp_core_validate_user_signup', array( __CLASS__, 'no_email_as_username' ), 20 );
	}

	public static function check_email_already_registered( $result ) {
		global $wpdb;

		$user_email = isset( $result['user_email'] ) ? sanitize_email( $result['user_email'] ) : '';
		if ( empty( $user_email ) ) {
			return $result;
		}

		$signups_table = $wpdb->base_prefix . 'signups';
		$users_table   = $wpdb->base_prefix . 'users';

		$signup_email_exists = 0;
		$user_email_exists   = 0;

		$signup_table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $signups_table ) );
		if ( $signup_table_exists === $signups_table ) {
			$signup_email_exists = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM `{$signups_table}` WHERE `user_email` = %s",
					$user_email
				)
			);
		}

		$user_email_exists = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM `{$users_table}` WHERE `user_email` = %s",
				$user_email
			)
		);

		if ( $signup_email_exists > 0 || $user_email_exists > 0 ) {
			if ( ! isset( $result['errors'] ) || ! is_wp_error( $result['errors'] ) ) {
				$result['errors'] = new WP_Error();
			}
			$result['errors']->add( 'user_email', __( 'This email address is already registered.', 'bp-registration-addon' ) );
		}

		return $result;
	}

	public static function restrict_username_characters( $valid, $username ) {
		return self::username_matches_rule( $username ) ? $valid : false;
	}

	public static function username_error_message( $translated_text, $text, $domain ) {
		$map = array(
			'letters_numbers'          => __( 'Usernames can contain only letters and numbers.', 'bp-registration-addon' ),
			'letters_numbers_dot'      => __( 'Usernames can contain only letters, numbers, and dots.', 'bp-registration-addon' ),
			'letters_numbers_dot_dash' => __( 'Usernames can contain only letters, numbers, dots, and dashes.', 'bp-registration-addon' ),
			'wordpress_default'        => __( 'Usernames can contain only letters, numbers, ., -, and @.', 'bp-registration-addon' ),
		);

		if ( 'Usernames can contain only letters, numbers, ., -, and @.' === $text ) {
			$mode = self::get_username_mode();
			return isset( $map[ $mode ] ) ? $map[ $mode ] : $translated_text;
		}

		return $translated_text;
	}

	public static function username_registration_errors( $errors, $sanitized_user_login, $user_email ) {
		$username = isset( $_POST['user_login'] ) ? wp_unslash( $_POST['user_login'] ) : '';

		if ( $username && ! self::username_matches_rule( $username ) ) {
			$errors->add( 'invalid_username', self::get_username_error_text() );
		}

		return self::dedupe_errors( $errors );
	}

	public static function no_email_as_username( $result ) {
		if ( ! empty( $result['user_name'] ) && is_email( $result['user_name'] ) ) {
			if ( ! isset( $result['errors'] ) || ! is_wp_error( $result['errors'] ) ) {
				$result['errors'] = new WP_Error();
			}
			$result['errors']->add( 'user_name', __( 'Usernames cannot be email addresses. Please choose another username.', 'bp-registration-addon' ) );
		}

		return $result;
	}

	public static function get_username_mode() {
		return get_option( self::OPTION_USERNAME_MODE, 'letters_numbers' );
	}

	public static function username_matches_rule( $username ) {
		$username = (string) $username;
		$mode = self::get_username_mode();

		switch ( $mode ) {
			case 'letters_numbers_dot':
				return (bool) preg_match( '/^[a-zA-Z0-9.]+$/', $username );
			case 'letters_numbers_dot_dash':
				return (bool) preg_match( '/^[a-zA-Z0-9.-]+$/', $username );
			case 'wordpress_default':
				return (bool) preg_match( '/^[A-Za-z0-9_\\.@-]+$/', $username );
			case 'letters_numbers':
			default:
				return (bool) preg_match( '/^[a-zA-Z0-9]+$/', $username );
		}
	}

	public static function get_username_error_text() {
		$map = array(
			'letters_numbers'          => __( 'Usernames can contain only letters and numbers.', 'bp-registration-addon' ),
			'letters_numbers_dot'      => __( 'Usernames can contain only letters, numbers, and dots.', 'bp-registration-addon' ),
			'letters_numbers_dot_dash' => __( 'Usernames can contain only letters, numbers, dots, and dashes.', 'bp-registration-addon' ),
			'wordpress_default'        => __( 'Usernames can contain only letters, numbers, ., -, and @.', 'bp-registration-addon' ),
		);

		$mode = self::get_username_mode();
		return isset( $map[ $mode ] ) ? $map[ $mode ] : $map['letters_numbers'];
	}

	private static function dedupe_errors( $errors ) {
		if ( ! is_wp_error( $errors ) ) {
			return $errors;
		}

		$deduped = new WP_Error();
		$seen = array();

		foreach ( $errors->errors as $code => $messages ) {
			foreach ( $messages as $message ) {
				$signature = md5( $code . '|' . wp_strip_all_tags( $message ) );
				if ( isset( $seen[ $signature ] ) ) {
					continue;
				}
				$seen[ $signature ] = true;
				$deduped->add( $code, wp_strip_all_tags( $message ) );
			}
		}

		return $deduped;
	}
}
