<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Core anti-spam: honeypot, time-trap, math captcha.
 */
class BPRA_AntiSpam {
  private static $instance = null;
  const HP_FIELD   = 'bpra_hp_website';
  const TS_FIELD   = 'bpra_ts';
  const MATH_A     = 'bpra_math_a';
  const MATH_B     = 'bpra_math_b';
  const MATH_ANS   = 'bpra_math_answer';
  const NONCE      = 'bpra_reg_nonce';

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    // Inject fields into BuddyPress register form.
    add_action( 'bp_before_registration_submit_buttons', array( $this, 'render_fields' ) );
    // Validate on signup.
    add_action( 'bp_signup_validate', array( $this, 'validate' ) );
  }

  public function render_fields() {
    if ( bpra_is_enabled( 'enable_honeypot' ) ) {
      echo '<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true"><label>Website<input type="text" name="' . esc_attr( self::HP_FIELD ) . '" value="" autocomplete="off" tabindex="-1" /></label></p>';
    }
    if ( bpra_is_enabled( 'enable_timetrap' ) ) {
      echo '<input type="hidden" name="' . esc_attr( self::TS_FIELD ) . '" value="' . esc_attr( time() ) . '" />';
    }
    if ( bpra_is_enabled( 'enable_math' ) ) {
      $a = wp_rand( 1, 9 );
      $b = wp_rand( 1, 9 );
      echo '<div class="bpra-math register-section"><label for="' . esc_attr( self::MATH_ANS ) . '">' . sprintf( esc_html__( 'Anti-spam: What is %1$d + %2$d?', 'bpra' ), $a, $b ) . ' <span class="bp-required-field-label">(required)</span></label>';
      echo '<input type="hidden" name="' . esc_attr( self::MATH_A ) . '" value="' . esc_attr( $a ) . '" />';
      echo '<input type="hidden" name="' . esc_attr( self::MATH_B ) . '" value="' . esc_attr( $b ) . '" />';
      echo '<input type="text" inputmode="numeric" pattern="[0-9]*" id="' . esc_attr( self::MATH_ANS ) . '" name="' . esc_attr( self::MATH_ANS ) . '" value="" autocomplete="off" /></div>';
    }
    wp_nonce_field( 'bpra_register', self::NONCE );
  }

  public function validate() {
    global $bp;
    $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();

    // Nonce (soft: only if present).
    if ( isset( $_POST[ self::NONCE ] ) && ! wp_verify_nonce( $_POST[ self::NONCE ], 'bpra_register' ) ) {
      $errors['signup_nonce'] = __( 'Security check failed. Please reload and try again.', 'bpra' );
      BPRA_Logger::log( 'nonce_fail', array() );
    }

    // Honeypot.
    if ( bpra_is_enabled( 'enable_honeypot' ) ) {
      if ( ! empty( $_POST[ self::HP_FIELD ] ) ) {
        $errors['signup_honeypot'] = __( 'Spam detected.', 'bpra' );
        BPRA_Logger::log( 'honeypot', array( 'value' => substr( (string) $_POST[ self::HP_FIELD ], 0, 64 ) ) );
      }
    }

    // Time-trap.
    if ( bpra_is_enabled( 'enable_timetrap' ) ) {
      $min = (int) bpra_setting( 'min_fill_seconds', 3 );
      $ts  = isset( $_POST[ self::TS_FIELD ] ) ? (int) $_POST[ self::TS_FIELD ] : 0;
      if ( $ts <= 0 || ( time() - $ts ) < $min ) {
        $errors['signup_timetrap'] = __( 'Form submitted too quickly. Please try again.', 'bpra' );
        BPRA_Logger::log( 'timetrap', array( 'delta' => ( $ts ? time() - $ts : -1 ) ) );
      }
    }

    // Math captcha.
    if ( bpra_is_enabled( 'enable_math' ) ) {
      $a = isset( $_POST[ self::MATH_A ] ) ? (int) $_POST[ self::MATH_A ] : -1;
      $b = isset( $_POST[ self::MATH_B ] ) ? (int) $_POST[ self::MATH_B ] : -1;
      $ans = isset( $_POST[ self::MATH_ANS ] ) ? trim( (string) $_POST[ self::MATH_ANS ] ) : '';
      if ( $ans === '' || ! ctype_digit( $ans ) || ( (int) $ans ) !== ( $a + $b ) ) {
        $errors['signup_math'] = __( 'Incorrect answer to the anti-spam question.', 'bpra' );
        BPRA_Logger::log( 'math_fail', array( 'a' => $a, 'b' => $b, 'ans' => $ans ) );
      }
    }

    if ( ! empty( $errors ) ) {
      $bp->signup->errors = $errors;
    }
  }
}
