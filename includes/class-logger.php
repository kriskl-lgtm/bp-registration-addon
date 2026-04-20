<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Rolling log of blocked registration attempts (stored in option, capped).
 */
class BPRA_Logger {
  const OPTION = 'bpra_blocked_log';
  const MAX    = 200;
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {}

  public static function log( $reason, $context = array() ) {
    if ( ! bpra_is_enabled( 'log_blocked' ) ) return;
    $entries = get_option( self::OPTION, array() );
    if ( ! is_array( $entries ) ) $entries = array();
    $entries[] = array(
      'time'    => current_time( 'mysql' ),
      'reason'  => sanitize_key( $reason ),
      'ip'      => class_exists( 'BPRA_RateLimit' ) ? BPRA_RateLimit::client_ip() : '',
      'ua'      => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( (string) $_SERVER['HTTP_USER_AGENT'], 0, 255 ) : '',
      'context' => $context,
    );
    if ( count( $entries ) > self::MAX ) {
      $entries = array_slice( $entries, -self::MAX );
    }
    update_option( self::OPTION, $entries, false );
  }

  public static function clear() {
    update_option( self::OPTION, array(), false );
  }

  public static function entries() {
    $e = get_option( self::OPTION, array() );
    return is_array( $e ) ? array_reverse( $e ) : array();
  }
}
