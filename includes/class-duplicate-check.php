<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Check for duplicate usernames and email addresses during BuddyPress registration.
 *
 * Covers:
 * - BuddyPress signup flow via bp_signup_validate
 * - WordPress/multisite flow via wpmu_validate_user_signup
 * - wp_users table (existing WordPress users)
 * - wp_signups table (pending/unactivated BuddyPress signups)
 * - username character restrictions (configurable)
 * - blocking email addresses used as usernames
 */
class BPRA_DuplicateCheck {

    const OPTION_USERNAME_MODE = 'bpra_username_mode';

    private static $instance = null;

    public static function instance() {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        // BuddyPress signup flow
        add_action( 'bp_signup_validate', array( $this, 'validate_bp' ), 8 );

        // WordPress / multisite registration flow
        add_filter( 'wpmu_validate_user_signup', array( $this, 'validate_wpmu' ), 20 );

        // Username character enforcement
        add_filter( 'validate_username', array( $this, 'restrict_characters' ), 10, 2 );
        add_filter( 'registration_errors', array( $this, 'username_registration_errors' ), 20, 3 );
        add_filter( 'gettext', array( $this, 'username_error_message' ), 20, 3 );

        // Block email addresses used as usernames (BuddyPress)
        add_filter( 'bp_core_validate_user_signup', array( $this, 'no_email_as_username' ), 20 );
    }

    // -------------------------------------------------------------------------
    // Static helpers
    // -------------------------------------------------------------------------

    public static function username_exists( $username ) {
        $username = sanitize_user( strtolower( trim( $username ) ) );
        if ( $username === '' ) {
            return false;
        }
        if ( username_exists( $username ) ) {
            return true;
        }
        global $wpdb;
        $signups_table = $wpdb->prefix . 'signups';
        if ( $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$signups_table} WHERE user_login = %s AND active = 0",
            $username
        ) ) > 0 ) {
            return true;
        }
        return false;
    }

    public static function email_exists( $email ) {
        $email = sanitize_email( strtolower( trim( $email ) ) );
        if ( $email === '' ) {
            return false;
        }
        if ( email_exists( $email ) ) {
            return true;
        }
        global $wpdb;
        $signups_table = $wpdb->base_prefix . 'signups';
        $exists = $wpdb->get_var( $wpdb->prepare(
            'SHOW TABLES LIKE %s',
            $signups_table
        ) );
        if ( $exists === $signups_table ) {
            if ( $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM `{$signups_table}` WHERE user_email = %s AND active = 0",
                $email
            ) ) > 0 ) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Username mode
    // -------------------------------------------------------------------------

    public static function get_username_mode() {
        return get_option( self::OPTION_USERNAME_MODE, 'letters_numbers' );
    }

    public static function username_matches_rule( $username ) {
        $username = (string) $username;
        switch ( self::get_username_mode() ) {
            case 'letters_numbers_dot':
                return (bool) preg_match( '/^[a-zA-Z0-9.]+$/', $username );
            case 'letters_numbers_dot_dash':
                return (bool) preg_match( '/^[a-zA-Z0-9.-]+$/', $username );
            case 'wordpress_default':
                return (bool) preg_match( '/^[A-Za-z0-9_\\.@-]+$/', $username );
            case 'letters_numbers':
            default:
                return (bool) preg_match( '/^[a-zA-Z0-9]+$/', $username );
        }
    }

    public static function get_username_error_text() {
        $map = array(
            'letters_numbers'          => __( 'Usernames can contain only letters and numbers.', 'bp-registration-addon' ),
            'letters_numbers_dot'      => __( 'Usernames can contain only letters, numbers, and dots.', 'bp-registration-addon' ),
            'letters_numbers_dot_dash' => __( 'Usernames can contain only letters, numbers, dots, and dashes.', 'bp-registration-addon' ),
            'wordpress_default'        => __( 'Usernames can contain only letters, numbers, ., -, and @.', 'bp-registration-addon' ),
        );
        $mode = self::get_username_mode();
        return isset( $map[ $mode ] ) ? $map[ $mode ] : $map['letters_numbers'];
    }

    // -------------------------------------------------------------------------
    // BuddyPress signup validation
    // -------------------------------------------------------------------------

    public function validate_bp() {
        global $bp;
        $errors = isset( $bp->signup->errors ) ? $bp->signup->errors : array();

        $username = isset( $_POST['signup_username'] ) ? trim( (string) $_POST['signup_username'] ) : '';
        if ( $username !== '' && ! isset( $errors['signup_username'] ) ) {
            if ( self::username_exists( $username ) ) {
                $errors['signup_username'] = __( 'That username is already taken. Please choose another.', 'bp-registration-addon' );
                BPRA_Logger::log( 'duplicate_username', array( 'username' => $username ) );
            }
            if ( ! self::username_matches_rule( $username ) ) {
                $errors['signup_username'] = self::get_username_error_text();
            }
            if ( is_email( $username ) ) {
                $errors['signup_username'] = __( 'Usernames cannot be email addresses. Please choose another username.', 'bp-registration-addon' );
            }
        }

        $email = isset( $_POST['signup_email'] ) ? trim( (string) $_POST['signup_email'] ) : '';
        if ( $email !== '' && ! isset( $errors['signup_email'] ) ) {
            if ( self::email_exists( $email ) ) {
                $errors['signup_email'] = __( 'That email address is already registered. Please use a different one or try logging in.', 'bp-registration-addon' );
                BPRA_Logger::log( 'duplicate_email', array( 'email_domain' => substr( $email, strpos( $email, '@' ) + 1 ) ) );
            }
        }

        if ( ! empty( $errors ) ) {
            $bp->signup->errors = $errors;
        }
    }

    // -------------------------------------------------------------------------
    // WordPress / multisite registration flow
    // -------------------------------------------------------------------------

    public function validate_wpmu( $result ) {
        global $wpdb;

        $user_email = isset( $result['user_email'] ) ? sanitize_email( $result['user_email'] ) : '';
        if ( ! empty( $user_email ) ) {
            if ( self::email_exists( $user_email ) ) {
                if ( ! isset( $result['errors'] ) || ! is_wp_error( $result['errors'] ) ) {
                    $result['errors'] = new WP_Error();
                }
                $result['errors']->add( 'user_email', __( 'This email address is already registered.', 'bp-registration-addon' ) );
            }
        }

        return $result;
    }

    // -------------------------------------------------------------------------
    // Username character rules
    // -------------------------------------------------------------------------

    public function restrict_characters( $valid, $username ) {
        return self::username_matches_rule( $username ) ? $valid : false;
    }

    public function username_registration_errors( $errors, $sanitized_user_login, $user_email ) {
        $username = isset( $_POST['user_login'] ) ? wp_unslash( $_POST['user_login'] ) : '';
        if ( $username && ! self::username_matches_rule( $username ) ) {
            $errors->add( 'invalid_username', self::get_username_error_text() );
        }
        return $this->dedupe_errors( $errors );
    }

    public function username_error_message( $translated_text, $text, $domain ) {
        if ( 'Usernames can contain only letters, numbers, ., -, and @.' === $text ) {
            return self::get_username_error_text();
        }
        return $translated_text;
    }

    // -------------------------------------------------------------------------
    // Block email as username (BuddyPress)
    // -------------------------------------------------------------------------

    public function no_email_as_username( $result ) {
        if ( ! empty( $result['user_name'] ) && is_email( $result['user_name'] ) ) {
            if ( ! isset( $result['errors'] ) || ! is_wp_error( $result['errors'] ) ) {
                $result['errors'] = new WP_Error();
            }
            $result['errors']->add( 'user_name', __( 'Usernames cannot be email addresses. Please choose another username.', 'bp-registration-addon' ) );
        }
        return $result;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function dedupe_errors( $errors ) {
        if ( ! is_wp_error( $errors ) ) {
            return $errors;
        }
        $deduped = new WP_Error();
        $seen    = array();
        foreach ( $errors->errors as $code => $messages ) {
            foreach ( $messages as $message ) {
                $sig = md5( $code . '|' . wp_strip_all_tags( $message ) );
                if ( isset( $seen[ $sig ] ) ) {
                    continue;
                }
                $seen[ $sig ] = true;
                $deduped->add( $code, wp_strip_all_tags( $message ) );
            }
        }
        return $deduped;
    }
}
