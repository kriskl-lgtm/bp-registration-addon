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
      __( 'BP Registration Addon', 'bp-registration-addon' ),
      __( 'BP Registration Addon', 'bp-registration-addon' ),
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
      <h1><?php esc_html_e( 'BP Registration Addon', 'bp-registration-addon' ); ?></h1>
      <?php if ( isset( $_GET['cleared'] ) ) echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Log cleared.', 'bp-registration-addon' ) . '</p></div>'; ?>
      <?php if ( isset( $_GET['settings-updated'] ) ) echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'bp-registration-addon' ) . '</p></div>'; ?>
      <form method="post" action="options.php">
        <?php settings_fields( 'bpra_group' ); ?>

        <h2><?php esc_html_e( 'Anti-Spam Protections', 'bp-registration-addon' ); ?></h2>
        <table class="form-table" role="presentation">
          <tr><th><?php esc_html_e( 'Honeypot field', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_honeypot]" value="1" <?php checked( ! empty( $s['enable_honeypot'] ) ); ?>> <?php esc_html_e( 'Add a hidden honeypot field bots will fill.', 'bp-registration-addon' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Time trap', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_timetrap]" value="1" <?php checked( ! empty( $s['enable_timetrap'] ) ); ?>> <?php esc_html_e( 'Reject forms submitted too quickly.', 'bp-registration-addon' ); ?></label><br>
              <label><?php esc_html_e( 'Minimum seconds:', 'bp-registration-addon' ); ?> <input type="number" min="0" name="bpra_settings[min_fill_seconds]" value="<?php echo esc_attr( $s['min_fill_seconds'] ); ?>" class="small-text"></label></td></tr>
          <tr><th><?php esc_html_e( 'Math captcha', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_math]" value="1" <?php checked( ! empty( $s['enable_math'] ) ); ?>> <?php esc_html_e( 'Require a simple arithmetic answer.', 'bp-registration-addon' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Disposable email blocklist', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_disposable]" value="1" <?php checked( ! empty( $s['enable_disposable'] ) ); ?>> <?php esc_html_e( 'Block known throwaway email domains (built-in list).', 'bp-registration-addon' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Rate limit', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_ratelimit]" value="1" <?php checked( ! empty( $s['enable_ratelimit'] ) ); ?>> <?php esc_html_e( 'Limit registrations per IP per hour.', 'bp-registration-addon' ); ?></label><br>
              <label><?php esc_html_e( 'Max per hour:', 'bp-registration-addon' ); ?> <input type="number" min="0" name="bpra_settings[ratelimit_per_hour]" value="<?php echo esc_attr( $s['ratelimit_per_hour'] ); ?>" class="small-text"></label></td></tr>
          <tr><th><?php esc_html_e( 'Username rules', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_username_rules]" value="1" <?php checked( ! empty( $s['enable_username_rules'] ) ); ?>> <?php esc_html_e( 'Enforce username heuristics.', 'bp-registration-addon' ); ?></label><br>
              <label><?php esc_html_e( 'Min length:', 'bp-registration-addon' ); ?> <input type="number" min="1" name="bpra_settings[min_username_length]" value="<?php echo esc_attr( $s['min_username_length'] ); ?>" class="small-text"></label><br>
              <label><input type="checkbox" name="bpra_settings[block_numeric_only]" value="1" <?php checked( ! empty( $s['block_numeric_only'] ) ); ?>> <?php esc_html_e( 'Block all-numeric usernames.', 'bp-registration-addon' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Log blocked attempts', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[log_blocked]" value="1" <?php checked( ! empty( $s['log_blocked'] ) ); ?>> <?php esc_html_e( 'Keep a rolling log (max 200 entries).', 'bp-registration-addon' ); ?></label></td></tr>
        </table>

        <h2><?php esc_html_e( 'Banned Email Domains', 'bp-registration-addon' ); ?></h2>
        <table class="form-table" role="presentation">
          <tr><th><?php esc_html_e( 'Enable banned domains', 'bp-registration-addon' ); ?></th>
            <td><label><input type="checkbox" name="bpra_settings[enable_banned_domains]" value="1" <?php checked( ! empty( $s['enable_banned_domains'] ) ); ?>> <?php esc_html_e( 'Block registrations from the domains listed below.', 'bp-registration-addon' ); ?></label></td></tr>
          <tr><th><?php esc_html_e( 'Domain list', 'bp-registration-addon' ); ?></th>
            <td>
              <textarea name="bpra_settings[banned_domains]" rows="10" cols="50" class="large-text code" placeholder="example.com&#10;spamdomain.net&#10;.subdomain-only.com"><?php echo esc_textarea( isset( $s['banned_domains'] ) ? $s['banned_domains'] : '' ); ?></textarea>
              <p class="description">
                <?php esc_html_e( 'Enter one domain per line. Any email address at a matching domain (including subdomains) will be blocked at registration.', 'bp-registration-addon' ); ?><br>
                <?php esc_html_e( 'Examples: "spam.com" blocks spam.com and *.spam.com. Prefix with a dot ".spam.com" to block subdomains only (but not spam.com itself).', 'bp-registration-addon' ); ?><br>
                <?php esc_html_e( 'You can paste full email addresses or URLs - the domain will be extracted automatically.', 'bp-registration-addon' ); ?>
              </p>
            </td></tr>
        </table>
        <?php submit_button(); ?>
      </form>

      <h2><?php esc_html_e( 'Blocked Attempts Log', 'bp-registration-addon' ); ?></h2>
      <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:10px;">
        <input type="hidden" name="action" value="bpra_clear_log">
        <?php wp_nonce_field( 'bpra_clear_log' ); ?>
        <button class="button"><?php esc_html_e( 'Clear log', 'bp-registration-addon' ); ?></button>
      </form>
      <table class="widefat striped"><thead><tr>
        <th><?php esc_html_e( 'Time', 'bp-registration-addon' ); ?></th>
        <th><?php esc_html_e( 'Reason', 'bp-registration-addon' ); ?></th>
        <th><?php esc_html_e( 'IP', 'bp-registration-addon' ); ?></th>
        <th><?php esc_html_e( 'Context', 'bp-registration-addon' ); ?></th>
      </tr></thead><tbody>
      <?php
      $entries = BPRA_Logger::entries();
      if ( empty( $entries ) ) {
        echo '<tr><td colspan="4">' . esc_html__( 'No blocked attempts recorded.', 'bp-registration-addon' ) . '</td></tr>';
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
