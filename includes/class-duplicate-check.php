<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Check for duplicate usernames and email addresses during BuddyPress registration.
 *
 * BuddyPress core already does basic checks, but this class adds an extra
 * validation layer that checks:
 *  - wp_users table (existing WordPress users)
 *  - wp_signups table (pending/unactivated BuddyPress signups)
 *
 * This prevents the scenario where a user registers with an email/username
 * that is already taken by a pending (unactivated) signup, which BuddyPress
 * core sometimes misses depending on configuration.
 */
class BPRA_DuplicateCheck {
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    // Run at priority 8 so it fires before our anti-spam checks (10+).
    add_action( 'bp_signup_validate', array( $this, 'validate' ), 8 );
  }

  /**
   * Check if a username already exists in wp_users or wp_signups.
   */
  public static function username_exists( $username ) {
    $username = sanitize_user( strtolower( trim( $username ) ) );
    if ( $username === '' ) return false;

    // Check existing WordPress users.
    if ( username_exists( $username ) ) return true;

    // Check pending BuddyPress signups.
    global $wpdb;
    $signups_table = $wpdb->prefix . 'signups';
    if ( $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$signups_table} WHERE user_login = %s AND active = 0", $username ) ) > 0 ) {
      return true;
    }

    return false;
  }

  /**
   * Check if an email already exists in wp_users or wp_signups.
   */
  public static function email_exists( $email ) {
    $email = sanitize_email( strtolower( trim( $email ) ) );
    if ( $email === '' ) return false;

    // Check existing WordPress users.
    if ( email_exists( $email ) ) return true;

    // Check pending BuddyPress signups.
    global $wpdb;
    $signups_table = $wpdb->prefix . 'signups';
    if ( $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$signups_table} WHERE user_email = %s AND active = 0", $email ) ) > 0 ) {
      return true;
    }

    return false;
  }

  /**
   * Validate during registration.
   */
  public function validate() {
    global $bp;
    $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();

    // Username check.
    $username = isset( $_POST['signup_username'] ) ? trim( (string) $_POST['signup_username'] ) : '';
    if ( $username !== '' && ! isset( $errors['signup_username'] ) ) {
      if ( self::username_exists( $username ) ) {
        $errors['signup_username'] = __( 'That username is already taken. Please choose another.', 'bp-registration-addon' );
        BPRA_Logger::log( 'duplicate_username', array( 'username' => $username ) );
      }
    }

    // Email check.
    $email = isset( $_POST['signup_email'] ) ? trim( (string) $_POST['signup_email'] ) : '';
    if ( $email !== '' && ! isset( $errors['signup_email'] ) ) {
      if ( self::email_exists( $email ) ) {
        $errors['signup_email'] = __( 'That email address is already registered. Please use a different one or try logging in.', 'bp-registration-addon' );
        BPRA_Logger::log( 'duplicate_email', array( 'email_domain' => substr( $email, strpos( $email, '@' ) + 1 ) ) );
      }
    }

    if ( ! empty( $errors ) ) {
      $bp->signup->errors = $errors;
    }
  }
}
