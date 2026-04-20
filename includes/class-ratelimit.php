<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Per-IP rate limit on registration attempts.
 */
class BPRA_RateLimit {
  private static $instance = null;
  const TKEY = 'bpra_rl_';

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    add_action( 'bp_signup_validate', array( $this, 'validate' ), 5 );
    add_action( 'bp_core_signup_user', array( $this, 'bump' ), 10, 0 );
  }

  public static function client_ip() {
    $ip = '';
    if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) { $parts = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ); $ip = trim( $parts[0] ); }
    elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) $ip = $_SERVER['REMOTE_ADDR'];
    return preg_replace( '/[^0-9a-fA-F\.:]/', '', $ip );
  }

  private static function key() {
    return self::TKEY . md5( self::client_ip() );
  }

  public function validate() {
    if ( ! bpra_is_enabled( 'enable_ratelimit' ) ) return;
    $max = (int) bpra_setting( 'ratelimit_per_hour', 5 );
    if ( $max <= 0 ) return;
    $count = (int) get_transient( self::key() );
    if ( $count >= $max ) {
      global $bp;
      $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();
      $errors['signup_ratelimit'] = __( 'Too many registration attempts from your network. Please try again later.', 'bpra' );
      $bp->signup->errors = $errors;
      BPRA_Logger::log( 'ratelimit', array( 'ip' => self::client_ip(), 'count' => $count ) );
    }
  }

  public function bump() {
    if ( ! bpra_is_enabled( 'enable_ratelimit' ) ) return;
    $k = self::key();
    $count = (int) get_transient( $k );
    set_transient( $k, $count + 1, HOUR_IN_SECONDS );
  }
}
