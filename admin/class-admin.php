<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Admin settings + blocked log viewer under Settings -> BP Registration Addon.
 */
class BPRA_Admin {

    private static $instance = null;

    public static function instance() {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action( 'admin_menu', array( $this, 'menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
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

    public function register_settings() {
        register_setting( 'bpra_group', 'bpra_settings', array(
            'sanitize_callback' => array( $this, 'sanitize_settings' ),
        ) );

        register_setting( 'bpra_group', 'bpra_username_mode', array(
            'type'              => 'string',
            'sanitize_callback' => array( $this, 'sanitize_username_mode' ),
            'default'           => 'letters_numbers',
        ) );
    }

    public function sanitize_username_mode( $value ) {
        $allowed = array(
            'letters_numbers',
            'letters_numbers_dot',
            'letters_numbers_dot_dash',
            'wordpress_default',
        );
        return in_array( $value, $allowed, true ) ? $value : 'letters_numbers';
    }

    public function sanitize_settings( $input ) {
        $clean = array();

        $checkboxes = array(
            'enable_honeypot',
            'enable_timetrap',
            'enable_math',
            'enable_disposable',
            'enable_ratelimit',
            'enable_username_rules',
            'block_numeric_only',
            'log_blocked',
            'enable_banned_domains',
            'enable_signup_nonce',
        );
        foreach ( $checkboxes as $key ) {
            $clean[ $key ] = ! empty( $input[ $key ] ) ? 1 : 0;
        }

        $clean['min_fill_seconds']    = isset( $input['min_fill_seconds'] ) ? absint( $input['min_fill_seconds'] ) : 5;
        $clean['ratelimit_per_hour']  = isset( $input['ratelimit_per_hour'] ) ? absint( $input['ratelimit_per_hour'] ) : 5;
        $clean['min_username_length'] = isset( $input['min_username_length'] ) ? max( 1, absint( $input['min_username_length'] ) ) : 4;
        $clean['max_username_length'] = isset( $input['max_username_length'] ) ? max( $clean['min_username_length'], absint( $input['max_username_length'] ) ) : 20;
        $clean['banned_domains']              = isset( $input['banned_domains'] ) ? sanitize_textarea_field( $input['banned_domains'] ) : '';
        $clean['blocked_usernames']           = isset( $input['blocked_usernames'] ) ? sanitize_textarea_field( $input['blocked_usernames'] ) : '';
        $clean['blocked_username_fragments']  = isset( $input['blocked_username_fragments'] ) ? sanitize_textarea_field( $input['blocked_username_fragments'] ) : '';

        return $clean;
    }

    public function clear_log() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'forbidden' );
        }
        check_admin_referer( 'bpra_clear_log' );
        BPRA_Logger::clear();
        wp_safe_redirect( admin_url( 'options-general.php?page=bpra&cleared=1' ) );
        exit;
    }

    public function render() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        $s  = bpra_get_settings();
        $um = get_option( 'bpra_username_mode', 'letters_numbers' );
        ?>
        <div class="wrap">
        <h1><?php esc_html_e( 'BP Registration Addon', 'bp-registration-addon' ); ?></h1>

        <?php if ( isset( $_GET['cleared'] ) ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Log cleared.', 'bp-registration-addon' ); ?></p></div>
        <?php endif; ?>
        <?php if ( isset( $_GET['settings-updated'] ) ) : ?>
            <div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings saved.', 'bp-registration-addon' ); ?></p></div>
        <?php endif; ?>

        <form method="post" action="options.php">
            <?php settings_fields( 'bpra_group' ); ?>

            <h2><?php esc_html_e( 'Anti-Spam Protections', 'bp-registration-addon' ); ?></h2>
            <table class="form-table" role="presentation">
            <tr>
                <th><?php esc_html_e( 'Honeypot field', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_honeypot]" value="1" <?php checked( ! empty( $s['enable_honeypot'] ) ); ?>>
                        <?php esc_html_e( 'Add a hidden honeypot field bots will fill.', 'bp-registration-addon' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Time trap', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_timetrap]" value="1" <?php checked( ! empty( $s['enable_timetrap'] ) ); ?>>
                        <?php esc_html_e( 'Reject forms submitted too quickly.', 'bp-registration-addon' ); ?>
                    </label>
                    <br><br>
                    <label>
                        <?php esc_html_e( 'Minimum seconds:', 'bp-registration-addon' ); ?>
                        <input type="number" min="0" name="bpra_settings[min_fill_seconds]" value="<?php echo esc_attr( $s['min_fill_seconds'] ); ?>" class="small-text">
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Math captcha', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_math]" value="1" <?php checked( ! empty( $s['enable_math'] ) ); ?>>
                        <?php esc_html_e( 'Require a simple arithmetic answer.', 'bp-registration-addon' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Disposable email blocklist', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_disposable]" value="1" <?php checked( ! empty( $s['enable_disposable'] ) ); ?>>
                        <?php esc_html_e( 'Block known throwaway email domains (built-in list).', 'bp-registration-addon' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Rate limit', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_ratelimit]" value="1" <?php checked( ! empty( $s['enable_ratelimit'] ) ); ?>>
                        <?php esc_html_e( 'Limit registrations per IP per hour.', 'bp-registration-addon' ); ?>
                    </label>
                    <br><br>
                    <label>
                        <?php esc_html_e( 'Max per hour:', 'bp-registration-addon' ); ?>
                        <input type="number" min="0" name="bpra_settings[ratelimit_per_hour]" value="<?php echo esc_attr( $s['ratelimit_per_hour'] ); ?>" class="small-text">
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'CSRF / nonce protection', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_signup_nonce]" value="1" <?php checked( ! empty( $s['enable_signup_nonce'] ) ); ?>>
                        <?php esc_html_e( 'Add and validate a nonce on the registration form.', 'bp-registration-addon' ); ?>
                    </label>
                    <p class="description"><?php esc_html_e( 'Use this as an extra request-authenticity check. Disable it if your registration template does not render the nonce field correctly.', 'bp-registration-addon' ); ?></p>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Username rules', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_username_rules]" value="1" <?php checked( ! empty( $s['enable_username_rules'] ) ); ?>>
                        <?php esc_html_e( 'Enforce username heuristics.', 'bp-registration-addon' ); ?>
                    </label>
                    <br><br>
                    <label>
                        <?php esc_html_e( 'Min length:', 'bp-registration-addon' ); ?>
                        <input type="number" min="1" max="50" name="bpra_settings[min_username_length]" value="<?php echo esc_attr( $s['min_username_length'] ); ?>" class="small-text">
                    </label>
                    &nbsp;&nbsp;
                    <label>
                        <?php esc_html_e( 'Max length:', 'bp-registration-addon' ); ?>
                        <input type="number" min="1" max="50" name="bpra_settings[max_username_length]" value="<?php echo esc_attr( isset( $s['max_username_length'] ) ? $s['max_username_length'] : 20 ); ?>" class="small-text">
                    </label>
                    <br><br>
                    <label>
                        <input type="checkbox" name="bpra_settings[block_numeric_only]" value="1" <?php checked( ! empty( $s['block_numeric_only'] ) ); ?>>
                        <?php esc_html_e( 'Block all-numeric usernames.', 'bp-registration-addon' ); ?>
                    </label>
                    <br><br>
                    <label for="bpra_username_mode">
                        <strong><?php esc_html_e( 'Username can contain:', 'bp-registration-addon' ); ?></strong>
                    </label><br>
                    <select id="bpra_username_mode" name="bpra_username_mode">
                        <option value="letters_numbers" <?php selected( $um, 'letters_numbers' ); ?>><?php esc_html_e( 'Only letters and numbers', 'bp-registration-addon' ); ?></option>
                        <option value="letters_numbers_dot" <?php selected( $um, 'letters_numbers_dot' ); ?>><?php esc_html_e( 'Letters, numbers and dot (.)', 'bp-registration-addon' ); ?></option>
                        <option value="letters_numbers_dot_dash" <?php selected( $um, 'letters_numbers_dot_dash' ); ?>><?php esc_html_e( 'Letters, numbers, dot (.) and dash (-)', 'bp-registration-addon' ); ?></option>
                        <option value="wordpress_default" <?php selected( $um, 'wordpress_default' ); ?>><?php esc_html_e( 'WordPress default: letters, numbers, ., -, @ and underscore', 'bp-registration-addon' ); ?></option>
                    </select>
                    <p class="description"><?php esc_html_e( 'Controls which characters are allowed in usernames at registration.', 'bp-registration-addon' ); ?></p>
                    <br>
                    <label for="bpra_blocked_usernames">
                        <strong><?php esc_html_e( 'Blocked usernames (exact match)', 'bp-registration-addon' ); ?></strong>
                    </label><br>
                    <textarea id="bpra_blocked_usernames" name="bpra_settings[blocked_usernames]" rows="6" cols="50" class="large-text code" placeholder="admin administrator support moderator"><?php echo esc_textarea( isset( $s['blocked_usernames'] ) ? $s['blocked_usernames'] : '' ); ?></textarea>
                    <p class="description"><?php esc_html_e( 'One username per line. Case-insensitive exact match.', 'bp-registration-addon' ); ?></p>
                    <br>
                    <label for="bpra_blocked_username_fragments">
                        <strong><?php esc_html_e( 'Blocked username fragments (partial match)', 'bp-registration-addon' ); ?></strong>
                    </label><br>
                    <textarea id="bpra_blocked_username_fragments" name="bpra_settings[blocked_username_fragments]" rows="6" cols="50" class="large-text code" placeholder="admin
staff
vulgarword"><?php echo esc_textarea( isset( $s['blocked_username_fragments'] ) ? $s['blocked_username_fragments'] : '' ); ?></textarea>
                    <p class="description"><?php esc_html_e( 'One fragment per line. If a username contains any of these strings it will be blocked.', 'bp-registration-addon' ); ?></p>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Log blocked attempts', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[log_blocked]" value="1" <?php checked( ! empty( $s['log_blocked'] ) ); ?>>
                        <?php esc_html_e( 'Keep a rolling log (max 200 entries).', 'bp-registration-addon' ); ?>
                    </label>
                </td>
            </tr>
            </table>

            <h2><?php esc_html_e( 'Banned Email Domains', 'bp-registration-addon' ); ?></h2>
            <table class="form-table" role="presentation">
            <tr>
                <th><?php esc_html_e( 'Enable banned domains', 'bp-registration-addon' ); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="bpra_settings[enable_banned_domains]" value="1" <?php checked( ! empty( $s['enable_banned_domains'] ) ); ?>>
                        <?php esc_html_e( 'Block registrations from the domains listed below.', 'bp-registration-addon' ); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th><?php esc_html_e( 'Domain list', 'bp-registration-addon' ); ?></th>
                <td>
                    <textarea name="bpra_settings[banned_domains]" rows="10" cols="50" class="large-text code" placeholder="mailinator.com
guerrillamail.com
tempmail.com"><?php echo esc_textarea( isset( $s['banned_domains'] ) ? $s['banned_domains'] : '' ); ?></textarea>
                    <p class="description">
                        <?php esc_html_e( 'Enter one domain per line. Any email address at a matching domain (including subdomains) will be blocked at registration.', 'bp-registration-addon' ); ?><br>
                        <?php esc_html_e( 'Examples: "spam.com" blocks spam.com and *.spam.com. Prefix with a dot ".spam.com" to block subdomains only (but not spam.com itself).', 'bp-registration-addon' ); ?><br>
                        <?php esc_html_e( 'You can paste full email addresses or URLs - the domain will be extracted automatically.', 'bp-registration-addon' ); ?>
                    </p>
                </td>
            </tr>
            </table>

            <?php submit_button(); ?>
        </form>

        <hr>

        <h2><?php esc_html_e( 'Blocked Attempts Log', 'bp-registration-addon' ); ?></h2>
        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
            <?php wp_nonce_field( 'bpra_clear_log' ); ?>
            <input type="hidden" name="action" value="bpra_clear_log">
            <?php submit_button( __( 'Clear log', 'bp-registration-addon' ), 'secondary', 'submit', false ); ?>
        </form>
        <br>
        <?php
        $log = BPRA_Logger::get();
        if ( empty( $log ) ) {
            echo '<p>' . esc_html__( 'No blocked attempts recorded.', 'bp-registration-addon' ) . '</p>';
        } else {
            echo '<table class="widefat striped"><thead><tr>';
            echo '<th>' . esc_html__( 'Time', 'bp-registration-addon' ) . '</th>';
            echo '<th>' . esc_html__( 'Reason', 'bp-registration-addon' ) . '</th>';
            echo '<th>' . esc_html__( 'IP', 'bp-registration-addon' ) . '</th>';
            echo '<th>' . esc_html__( 'Context', 'bp-registration-addon' ) . '</th>';
            echo '</tr></thead><tbody>';
            foreach ( array_reverse( $log ) as $entry ) {
                echo '<tr>';
                echo '<td>' . esc_html( isset( $entry['time'] ) ? $entry['time'] : '' ) . '</td>';
                echo '<td>' . esc_html( isset( $entry['reason'] ) ? $entry['reason'] : '' ) . '</td>';
                echo '<td>' . esc_html( isset( $entry['ip'] ) ? $entry['ip'] : '' ) . '</td>';
                $ctx = isset( $entry['context'] ) ? $entry['context'] : array();
                echo '<td>' . esc_html( is_array( $ctx ) ? wp_json_encode( $ctx ) : $ctx ) . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
        }
        ?>
        </div>
        <?php
    }
}
