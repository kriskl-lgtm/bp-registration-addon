<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Blocks known disposable / throwaway email domains.
 */
class BPRA_Disposable {
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    add_action( 'bp_signup_validate', array( $this, 'validate' ), 20 );
  }

  public static function domains() {
    $list = array(
      'mailinator.com','guerrillamail.com','guerrillamail.net','guerrillamail.org','guerrillamail.biz',
      'sharklasers.com','grr.la','10minutemail.com','10minutemail.net','tempmail.com','temp-mail.org',
      'trashmail.com','trashmail.net','yopmail.com','yopmail.fr','yopmail.net','dispostable.com',
      'fakeinbox.com','maildrop.cc','getnada.com','nada.email','mytemp.email','tempail.com',
      'throwawaymail.com','mohmal.com','mintemail.com','mailnesia.com','spambog.com','spamgourmet.com',
      'tempr.email','discard.email','burnermail.io','emailondeck.com','einrot.com','spam4.me',
      'tempinbox.com','mail-temporaire.fr','anonbox.net','tempmailaddress.com','emltmp.com',
      'moakt.com','tmails.net','tmpmail.org','tmpmail.net','luxusmail.org','inboxbear.com',
      'harakirimail.com','mailcatch.com','mailnull.com','mvrht.com','mytrashmail.com','nwytg.net',
      'tempemail.com','tempemail.net','tempmail.us','wegwerfemail.de','zetmail.com'
    );
    return apply_filters( 'bpra_disposable_domains', array_unique( array_map( 'strtolower', $list ) ) );
  }

  public function validate() {
    if ( ! bpra_is_enabled( 'enable_disposable' ) ) return;
    global $bp;
    $email = isset( $_POST['signup_email'] ) ? strtolower( trim( (string) $_POST['signup_email'] ) ) : '';
    if ( $email === '' || strpos( $email, '@' ) === false ) return;
    $domain = substr( $email, strpos( $email, '@' ) + 1 );
    $bad = self::domains();
    foreach ( $bad as $d ) {
      if ( $domain === $d || ( strlen( $domain ) > strlen( $d ) && substr( $domain, - ( strlen( $d ) + 1 ) ) === '.' . $d ) ) {
        $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();
        $errors['signup_email'] = __( 'Please use a non-disposable email address.', 'bpra' );
        $bp->signup->errors = $errors;
        BPRA_Logger::log( 'disposable', array( 'domain' => $domain ) );
        return;
      }
    }
  }
}
