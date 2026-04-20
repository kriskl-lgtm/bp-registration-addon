<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Admin settings + blocked log viewer under Settings -> BP Registration Addon.
 */
class BPRA_Admin {
  private static $instance = null;

  public static function instance() {
    if ( self::$instance === null ) self::$instance = new self();
    return self::$instance;
  }

  private function __construct() {
    add_action( 'admin_menu', array( $this, 'menu' ) );
    add_action( 'admin_post_bpra_clear_log', array( $this, 'clear_log' ) );
  }

  public function menu() {
    add_options_page(
      __( 'BP Registration Addon', 'bpra' ),
      __( 'BP Registration Addon', 'bpra' ),
      'manage_options',
      'bpra',
      array( $this, 'render' )
    );
  }

  public function clear_log() {
    if ( ! current_user_can( 'manage_options' ) ) wp_die( 'forbidden' );
    check_admin_referer( 'bpra_clear_log' );
    BPRA_Logger::clear();
    wp_safe_redirect( admin_url( 'options-general.php?page=bpra&cleared=1' ) );
    exit;
  }

  public function render() {
    if ( ! current_user_can( 'manage_options' ) ) return;
    $s = bpra_get_settings();
    ?>
    <div class="wrap">
      <h1><?php esc_html_e( 'BP Registration Addon', 'bpra' ); ?></h1>
      <?php if ( isset( $_GET['cleared'] ) ) echo '<div class="notice notice-success"><p>' . esc_html__( 'Log cleared.', 'bpra' ) . '</p></div>'; ?>
      <form method="post" action="options.php">
        <?php settings_fields( 'bpra_group' ); ?>
        <table class="form-table" role="presentation">
          <tr><th><?php esc_html_e( 'Honeypot field', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_honeypot]" value="1" <?php checked( ! empty( $s['enable_honeypot'] ) ); ?>> <?php esc_html_e( 'Add a hidden honeypot field bots will fill.', 'bpra' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Time trap', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_timetrap]" value="1" <?php checked( ! empty( $s['enable_timetrap'] ) ); ?>> <?php esc_html_e( 'Reject forms submitted too quickly.', 'bpra' ); ?></label><br>
              <label><?php esc_html_e( 'Minimum seconds:', 'bpra' ); ?> <input type="number" min="0" name="bpra_settings[min_fill_seconds]" value="<?php echo esc_attr( $s['min_fill_seconds'] ); ?>" class="small-text"></label></td></tr>
          <tr><th><?php esc_html_e( 'Math captcha', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_math]" value="1" <?php checked( ! empty( $s['enable_math'] ) ); ?>> <?php esc_html_e( 'Require a simple arithmetic answer.', 'bpra' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Disposable email blocklist', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_disposable]" value="1" <?php checked( ! empty( $s['enable_disposable'] ) ); ?>> <?php esc_html_e( 'Block known throwaway email domains.', 'bpra' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Rate limit', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_ratelimit]" value="1" <?php checked( ! empty( $s['enable_ratelimit'] ) ); ?>> <?php esc_html_e( 'Limit registrations per IP per hour.', 'bpra' ); ?></label><br>
              <label><?php esc_html_e( 'Max per hour:', 'bpra' ); ?> <input type="number" min="0" name="bpra_settings[ratelimit_per_hour]" value="<?php echo esc_attr( $s['ratelimit_per_hour'] ); ?>" class="small-text"></label></td></tr>
          <tr><th><?php esc_html_e( 'Username rules', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_username_rules]" value="1" <?php checked( ! empty( $s['enable_username_rules'] ) ); ?>> <?php esc_html_e( 'Enforce username heuristics.', 'bpra' ); ?></label><br>
              <label><?php esc_html_e( 'Min length:', 'bpra' ); ?> <input type="number" min="1" name="bpra_settings[min_username_length]" value="<?php echo esc_attr( $s['min_username_length'] ); ?>" class="small-text"></label><br>
              <label><input type="checkbox" name="bpra_settings[block_numeric_only]" value="1" <?php checked( ! empty( $s['block_numeric_only'] ) ); ?>> <?php esc_html_e( 'Block all-numeric usernames.', 'bpra' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Log blocked attempts', 'bpra' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[log_blocked]" value="1" <?php checked( ! empty( $s['log_blocked'] ) ); ?>> <?php esc_html_e( 'Keep a rolling log (max 200).', 'bpra' ); ?></label></td></tr>
        </table>
        <?php submit_button(); ?>
      </form>

      <h2><?php esc_html_e( 'Blocked attempts', 'bpra' ); ?></h2>
      <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:10px;">
        <input type="hidden" name="action" value="bpra_clear_log">
        <?php wp_nonce_field( 'bpra_clear_log' ); ?>
        <button class="button"><?php esc_html_e( 'Clear log', 'bpra' ); ?></button>
      </form>
      <table class="widefat striped"><thead><tr>
        <th><?php esc_html_e( 'Time', 'bpra' ); ?></th>
        <th><?php esc_html_e( 'Reason', 'bpra' ); ?></th>
        <th><?php esc_html_e( 'IP', 'bpra' ); ?></th>
        <th><?php esc_html_e( 'Context', 'bpra' ); ?></th>
      </tr></thead><tbody>
      <?php
      $entries = BPRA_Logger::entries();
      if ( empty( $entries ) ) {
        echo '<tr><td colspan="4">' . esc_html__( 'No blocked attempts recorded.', 'bpra' ) . '</td></tr>';
      } else {
        foreach ( $entries as $e ) {
          echo '<tr>';
          echo '<td>' . esc_html( $e['time'] ) . '</td>';
          echo '<td>' . esc_html( $e['reason'] ) . '</td>';
          echo '<td>' . esc_html( $e['ip'] ) . '</td>';
          echo '<td><code>' . esc_html( wp_json_encode( $e['context'] ) ) . '</code></td>';
          echo '</tr>';
        }
      }
      ?>
      </tbody></table>
    </div>
    <?php
  }
}
