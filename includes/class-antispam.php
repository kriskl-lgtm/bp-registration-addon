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
    // Inject fields just before the submit buttons (outside the 2-column grid).
    add_action( 'bp_before_registration_submit_buttons', array( $this, 'render_fields' ) );
    // Scoped CSS on the register page.
    add_action( 'wp_head', array( $this, 'print_css' ) );
    // Validate on signup.
    add_action( 'bp_signup_validate', array( $this, 'validate' ) );
  }

  public function print_css() {
    if ( ! function_exists( 'bp_is_register_page' ) || ! bp_is_register_page() ) return;
    ?>
    <style id="bpra-inline-css">
      .bpra-antispam{
        clear:both;display:block;width:100%;box-sizing:border-box;
        margin:24px 0 8px;padding:16px 18px;
        background:#f7f8fa;border:1px solid #e3e6ea;border-radius:6px;
      }
      .bpra-antispam label{
        display:block;margin:0 0 8px;font-weight:600;
        white-space:normal;word-break:normal;overflow-wrap:normal;
        font-size:15px;line-height:1.4;
      }
      .bpra-antispam input[type="text"]{
        display:block;width:140px;max-width:100%;
        padding:8px 10px;font-size:16px;line-height:1.4;
        border:1px solid #c7ccd1;border-radius:4px;background:#fff;
      }
      .bpra-antispam .bpra-hint{
        display:block;margin-top:6px;font-size:12px;color:#6b7280;font-weight:400;
      }
      .bpra-hp{position:absolute!important;left:-9999px!important;top:-9999px!important;width:1px!important;height:1px!important;overflow:hidden!important;}
    </style>
    <?php
  }

  public function render_fields() {
    // Force-close any open column/grid wrapper from the theme/plugin above,
    // then open a clean full-width block for our anti-spam UI.
    echo '</div></div><div class="bpra-antispam-wrap" style="clear:both;width:100%;display:block;">';

    if ( bpra_is_enabled( 'enable_honeypot' ) ) {
      echo '<p class="bpra-hp" aria-hidden="true"><label>Website<input type="text" name="' . esc_attr( self::HP_FIELD ) . '" value="" autocomplete="off" tabindex="-1" /></label></p>';
    }
    if ( bpra_is_enabled( 'enable_timetrap' ) ) {
      echo '<input type="hidden" name="' . esc_attr( self::TS_FIELD ) . '" value="' . esc_attr( time() ) . '" />';
    }
    if ( bpra_is_enabled( 'enable_math' ) ) {
      $a = wp_rand( 1, 9 );
      $b = wp_rand( 1, 9 );
      echo '<div class="bpra-antispam">';
      echo '<label for="' . esc_attr( self::MATH_ANS ) . '">' . sprintf( esc_html__( 'Anti-spam check: what is %1$d + %2$d?', 'bp-registration-addon' ), $a, $b ) . ' <span style="color:#b91c1c;">*</span></label>';
      echo '<input type="hidden" name="' . esc_attr( self::MATH_A ) . '" value="' . esc_attr( $a ) . '" />';
      echo '<input type="hidden" name="' . esc_attr( self::MATH_B ) . '" value="' . esc_attr( $b ) . '" />';
      echo '<input type="text" inputmode="numeric" pattern="[0-9]*" id="' . esc_attr( self::MATH_ANS ) . '" name="' . esc_attr( self::MATH_ANS ) . '" value="" autocomplete="off" />';
      echo '<span class="bpra-hint">' . esc_html__( 'Please type the answer as a number to prove you are human.', 'bp-registration-addon' ) . '</span>';
      echo '</div>';
    }
    wp_nonce_field( 'bpra_register', self::NONCE );

    // Re-open the structural wrappers we closed so BuddyPress markup stays balanced.
    echo '</div><div><div>';
  }

  public function validate() {
    global $bp;
    $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();

    if ( isset( $_POST[ self::NONCE ] ) && ! wp_verify_nonce( $_POST[ self::NONCE ], 'bpra_register' ) ) {
      $errors['signup_nonce'] = __( 'Security check failed. Please reload and try again.', 'bp-registration-addon' );
      BPRA_Logger::log( 'nonce_fail', array() );
    }

    if ( bpra_is_enabled( 'enable_honeypot' ) ) {
      if ( ! empty( $_POST[ self::HP_FIELD ] ) ) {
        $errors['signup_honeypot'] = __( 'Spam detected.', 'bp-registration-addon' );
        BPRA_Logger::log( 'honeypot', array( 'value' => substr( (string) $_POST[ self::HP_FIELD ], 0, 64 ) ) );
      }
    }

    if ( bpra_is_enabled( 'enable_timetrap' ) ) {
      $min = (int) bpra_setting( 'min_fill_seconds', 3 );
      $ts  = isset( $_POST[ self::TS_FIELD ] ) ? (int) $_POST[ self::TS_FIELD ] : 0;
      if ( $ts <= 0 || ( time() - $ts ) < $min ) {
        $errors['signup_timetrap'] = __( 'Form submitted too quickly. Please try again.', 'bp-registration-addon' );
        BPRA_Logger::log( 'timetrap', array( 'delta' => ( $ts ? time() - $ts : -1 ) ) );
      }
    }

    if ( bpra_is_enabled( 'enable_math' ) ) {
      $a = isset( $_POST[ self::MATH_A ] ) ? (int) $_POST[ self::MATH_A ] : -1;
      $b = isset( $_POST[ self::MATH_B ] ) ? (int) $_POST[ self::MATH_B ] : -1;
      $ans = isset( $_POST[ self::MATH_ANS ] ) ? trim( (string) $_POST[ self::MATH_ANS ] ) : '';
      if ( $ans === '' || ! ctype_digit( $ans ) || ( (int) $ans ) !== ( $a + $b ) ) {
        $errors['signup_math'] = __( 'Incorrect answer to the anti-spam question.', 'bp-registration-addon' );
        BPRA_Logger::log( 'math_fail', array( 'a' => $a, 'b' => $b, 'ans' => $ans ) );
      }
    }

    if ( ! empty( $errors ) ) {
      $bp->signup->errors = $errors;
    }
  }
}
