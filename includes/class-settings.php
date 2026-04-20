<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class BPRA_Settings {
  private static $instance = null;
  const OPTION = 'bpra_settings';

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    add_action( 'admin_init', array( $this, 'register' ) );
  }

  public function register() {
    register_setting( 'bpra_group', self::OPTION, array( $this, 'sanitize' ) );
  }

  public function sanitize( $input ) {
    $out = array();
    $keys_bool = array( 'enable_honeypot','enable_timetrap','enable_math','enable_disposable','enable_ratelimit','enable_username_rules','block_numeric_only','log_blocked','enable_banned_domains' );
    foreach ( $keys_bool as $k ) $out[ $k ] = ! empty( $input[ $k ] ) ? 1 : 0;
    $out['min_fill_seconds']    = isset( $input['min_fill_seconds'] ) ? max( 0, (int) $input['min_fill_seconds'] ) : 3;
    $out['ratelimit_per_hour']  = isset( $input['ratelimit_per_hour'] ) ? max( 0, (int) $input['ratelimit_per_hour'] ) : 5;
    $out['min_username_length'] = isset( $input['min_username_length'] ) ? max( 1, (int) $input['min_username_length'] ) : 4;

    // Banned domains textarea: one per line, normalise.
    $raw = isset( $input['banned_domains'] ) ? (string) $input['banned_domains'] : '';
    $lines = preg_split( '/[\r\n,]+/', $raw );
    $clean = array();
    foreach ( $lines as $line ) {
      $d = strtolower( trim( $line ) );
      if ( $d === '' ) continue;
      $d = preg_replace( '#^https?://#', '', $d );
      if ( strpos( $d, '@' ) !== false ) $d = substr( $d, strpos( $d, '@' ) + 1 );
      $d = trim( $d, "/ \t" );
      if ( preg_match( '/^\.?[a-z0-9][a-z0-9\.-]*\.[a-z]{2,}$/', $d ) ) {
        $clean[] = $d;
      }
    }
    $clean = array_values( array_unique( $clean ) );
    $out['banned_domains'] = implode( "\n", $clean );

    return $out;
  }
}
