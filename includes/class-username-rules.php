<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Username heuristics: min length, block numeric-only, block obvious spam patterns.
 */
class BPRA_UsernameRules {
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    add_action( 'bp_signup_validate', array( $this, 'validate' ), 15 );
  }

  public function validate() {
    if ( ! bpra_is_enabled( 'enable_username_rules' ) ) return;
    global $bp;
    $user = isset( $_POST['signup_username'] ) ? trim( (string) $_POST['signup_username'] ) : '';
    if ( $user === '' ) return;

    $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();
    $min    = (int) bpra_setting( 'min_username_length', 4 );

    if ( mb_strlen( $user ) < $min ) {
      $errors['signup_username'] = sprintf( __( 'Username must be at least %d characters.', 'bpra' ), $min );
      BPRA_Logger::log( 'username_short', array( 'user' => $user ) );
    } elseif ( bpra_is_enabled( 'block_numeric_only' ) && ctype_digit( $user ) ) {
      $errors['signup_username'] = __( 'Username cannot be all numbers.', 'bpra' );
      BPRA_Logger::log( 'username_numeric', array( 'user' => $user ) );
    } elseif ( preg_match( '/(.)\1{4,}/u', $user ) ) {
      $errors['signup_username'] = __( 'Username contains suspicious repeated characters.', 'bpra' );
      BPRA_Logger::log( 'username_repeat', array( 'user' => $user ) );
    }

    $bp->signup->errors = $errors;
  }
}
