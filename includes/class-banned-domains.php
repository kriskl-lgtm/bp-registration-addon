<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Admin-managed banned email domains.
 *
 * Similar in spirit to "WP Ban Registration Domain" by BuddyDev. Administrators
 * enter one domain per line (e.g. example.com) in Settings -> BP Registration
 * Addon. Any registration using an email at a matching domain (or subdomain)
 * is blocked with a friendly error. Supports wildcard leading dot (".foo.com")
 * to explicitly match subdomains only.
 */
class BPRA_BannedDomains {
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    // Run before the disposable check so admin list takes precedence.
    add_action( 'bp_signup_validate', array( $this, 'validate' ), 15 );
  }

  /**
   * Parse the textarea option into a clean list of lowercase domains.
   *
   * @return array
   */
  public static function get_list() {
    $raw = (string) bpra_setting( 'banned_domains', '' );
    if ( $raw === '' ) return array();
    $lines = preg_split( '/[\r\n,]+/', $raw );
    $out   = array();
    foreach ( $lines as $line ) {
      $d = strtolower( trim( $line ) );
      if ( $d === '' ) continue;
      // Strip protocol, path, @, and surrounding whitespace if user pasted an email/URL.
      $d = preg_replace( '#^https?://#', '', $d );
      if ( strpos( $d, '@' ) !== false ) {
        $d = substr( $d, strpos( $d, '@' ) + 1 );
      }
      $d = trim( $d, "/ \t" );
      // Very loose validity check: must contain a dot and only allowed chars.
      if ( ! preg_match( '/^\.?[a-z0-9][a-z0-9\.-]*\.[a-z]{2,}$/', $d ) ) continue;
      $out[] = $d;
    }
    return array_values( array_unique( $out ) );
  }

  /**
   * True if the given email address matches any banned entry.
   */
  public static function is_banned( $email ) {
    $email = strtolower( trim( (string) $email ) );
    if ( $email === '' || strpos( $email, '@' ) === false ) return false;
    $domain = substr( $email, strpos( $email, '@' ) + 1 );
    foreach ( self::get_list() as $entry ) {
      if ( $entry === '' ) continue;
      if ( $entry[0] === '.' ) {
        // Subdomain-only match, e.g. ".example.com" blocks a.example.com but not example.com.
        $suffix = $entry; // includes leading dot
        if ( strlen( $domain ) > strlen( $suffix ) && substr( $domain, - strlen( $suffix ) ) === $suffix ) {
          return true;
        }
      } else {
        if ( $domain === $entry ) return true;
        if ( strlen( $domain ) > strlen( $entry ) + 1 && substr( $domain, - ( strlen( $entry ) + 1 ) ) === '.' . $entry ) {
          return true;
        }
      }
    }
    return false;
  }

  public function validate() {
    if ( ! bpra_is_enabled( 'enable_banned_domains' ) ) return;
    global $bp;
    $email = isset( $_POST['signup_email'] ) ? (string) $_POST['signup_email'] : '';
    if ( $email === '' ) return;
    if ( self::is_banned( $email ) ) {
      $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();
      $errors['signup_email'] = __( 'Registrations from this email domain are not allowed.', 'bp-registration-addon' );
      $bp->signup->errors = $errors;
      $domain = substr( strtolower( $email ), strpos( $email, '@' ) + 1 );
      if ( class_exists( 'BPRA_Logger' ) ) {
        BPRA_Logger::log( 'banned_domain', array( 'domain' => $domain ) );
      }
    }
  }
}
