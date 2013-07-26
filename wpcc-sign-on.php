<?php
/**
 * Plugin Name: WPCC Sign On
 * Plugin URI: http://wordpress.org/plugins/wpcc-sign-on/
 * Description: A single-sign-on via WordPress.com for your WordPress.org site!
 * Author: George Stephanis
 * Version: 1.0
 * Author URI: http://stephanis.info/
 */

class WPCC_Sign_On {
	static $instance = null;

	var $request_token_url,
		$authenticate_url,
		$client_id,
		$client_secret,
		$redirect_url,
		$secret,
		$user_data;

	function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$instance = $this;

		$this->request_token_url = 'https://public-api.wordpress.com/oauth2/token';
		$this->authenticate_url  = 'https://public-api.wordpress.com/oauth2/authenticate';
		$this->user_data_url     = 'https://public-api.wordpress.com/rest/v1/me/';
		$this->client_id         = get_option( 'wpcc_sign_on_client_id' );
		$this->client_secret     = get_option( 'wpcc_sign_on_client_secret' );
		$this->redirect_url      = wp_login_url();

		add_action( 'admin_init', array( $this, 'admin_init' ) );

		if ( empty( $this->client_id ) ) {
			return;
		}

		add_action( 'login_init',            array( $this, 'login_init' )            );
		add_action( 'login_enqueue_scripts', array( $this, 'login_enqueue_scripts' ) );
		add_action( 'login_form',            array( $this, 'login_form' )            );
	}

	function admin_init() {
		register_setting( 'general', 'wpcc_sign_on_client_id', 'intval' );
		add_settings_field( 'wpcc_sign_on_client_id', '<label for="wpcc_sign_on_client_id">WPCC Client ID</label>' , array( $this, 'wpcc_sign_on_client_id_cb' ) , 'general' );
		register_setting( 'general', 'wpcc_sign_on_client_secret', 'sanitize_text_field' );
		add_settings_field( 'wpcc_sign_on_client_secret', '<label for="wpcc_sign_on_client_secret">WPCC Client Secret</label>' , array( $this, 'wpcc_sign_on_client_secret_cb' ) , 'general' );
	}

	function wpcc_sign_on_client_id_cb() {
		$value = $this->client_id;
		echo '<input type="text" id="wpcc_sign_on_client_id" name="wpcc_sign_on_client_id" value="' . esc_attr( $value ) . '" />';
	}

	function wpcc_sign_on_client_secret_cb() {
		$value = $this->client_secret;
		echo '<input type="password" id="wpcc_sign_on_client_secret" name="wpcc_sign_on_client_secret" value="' . esc_attr( $value ) . '" />';
	}

	function login_init() {
		// Set the wpcc_state
		$this->wpcc_state = md5( mt_rand() );
		if ( isset( $_COOKIE['wpcc_state'] ) ) {
			$this->wpcc_state = $_COOKIE['wpcc_state'];
		} else {
			setcookie( 'wpcc_state', $this->wpcc_state );
		}

		// If they just got forwarded back ...
		if ( isset( $_GET['code'] ) ) {
			if ( empty( $_GET['state'] ) ) {
				wp_die( __( 'Warning! State variable missing after authentication.', 'wpcc-sign-on' ) );
			}

			if ( $_GET['state'] != $this->wpcc_state ) {
				wp_die( __( 'Warning! State mismatch. Authentication attempt may have been compromised.', 'wpcc-sign-on' ) );
			}

			$args = array(
				'client_id'     => $this->client_id,
				'redirect_uri'  => $this->redirect_url,
				'client_secret' => $this->client_secret,
				'code'          => sanitize_text_field( $_GET['code'] ), // The code from the previous request
				'grant_type'    => 'authorization_code',
			);

			$response = wp_remote_post( $this->request_token_url, array( 'body' => $args ) );

			if ( is_wp_error( $response ) ) {
				wp_die( __( 'Warning! Could not confirm request token url!', 'wpcc-sign-on' ) );
			}

			$this->secret = json_decode( wp_remote_retrieve_body( $response ) );

			$args = array(
				'headers' => array(
					'Authorization' => sprintf( 'Bearer %s', $this->secret->access_token ),
				),
			);

			$response = wp_remote_get( $this->user_data_url, $args );
	
			if ( is_wp_error( $response ) ) {
				wp_die( __( 'Warning! Could not fetch user data!', 'wpcc-sign-on' ) );
			}

			$this->user_data = json_decode( wp_remote_retrieve_body( $response ) );

			$this->auth_user( $this->user_data );
		}
	}

	function login_enqueue_scripts() {
		wp_enqueue_style( 'wpcc-sign-on', plugins_url( 'wpcc-sign-on.css', __FILE__ ), 0, filemtime( dirname( __FILE__ ) . '/wpcc-sign-on.css' ) );
		wp_enqueue_script( 'wpcc-sign-on', plugins_url( 'wpcc-sign-on.js', __FILE__ ), array( 'jquery' ), filemtime( dirname( __FILE__ ) . '/wpcc-sign-on.js'  ) );
	}

	function login_form() {
		echo self::button();
	}

	function button() {
		$args = array(
			'response_type' => 'code',
			'client_id'     => $this->client_id,
			'state'         => $this->wpcc_state,
			'redirect_uri'  => $this->redirect_url,
		);

		$url = add_query_arg( $args, $this->authenticate_url );

		return sprintf( '<a id="wpcc-sign-on" href="%1$s"><img src="//s0.wp.com/i/wpcc-button.png" width="231" /></a>', esc_url( $url ) );
	}

	function auth_user( $user_data ) {

		if ( ! $user_data->verified ) {
			return false;
		}

		$user = $this->get_user_by_wpcom_id( $user_data->ID );

		// If we don't have one by wpcom_user_id, try by the email?
		if ( empty( $user ) ) {
			$user = get_user_by( 'email', $user_data->email );
			if ( $user ) {
				update_user_meta( $user->ID, 'wpcom_user_id', $user_data->ID );
			}
		}

		// If we've still got nothing, create the user.
		if ( empty( $user ) && get_option( 'users_can_register' ) ) {
			$username = $user_data->username;

			if ( username_exists( $username ) ) {
				$username .= '_' . $user_data->ID;
			}

			if ( username_exists( $username ) )
				$username .= '_' . mt_rand();

			$password = wp_generate_password( 12, true );
			$user_id  = wp_create_user( $username, $password, $user_data->email );
			$user     = get_userdata( $user_id );

			$user->display_name = $user_data->display_name;
			wp_update_user( $user );

			update_user_meta( $user->ID, 'wpcom_user_id', $user_data->ID );
		}

		if ( $user ) {
			wp_set_auth_cookie( $user->ID );
	
			$redirect_to = ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : site_url();
			wp_safe_redirect( apply_filters( 'wpcc_sign_on_redirect', $redirect_to ) );
			exit;
		}

		add_action( 'login_message', array( $this, 'cant_find_user' ) );
	}

	function get_user_by_wpcom_id( $wpcom_user_id ) {
		$user_query = new WP_User_Query( array(
			'meta_key'   => 'wpcom_user_id',
			'meta_value' => intval( $wpcom_user_id ),
		) );

		$users = $user_query->get_results();

		return ( is_array( $users ) && ! empty( $users ) ) ? array_shift( $users ) : $users;
	}

	function cant_find_user( $message ) {
		$err_format = __( 'We couldn\t find an account with the email <strong><code>%1$s</code></strong> to log you in with.  If you already have an account on <strong>%2$s</strong>, please make sure that <strong><code>%1$s</code></strong> is configured as the email address.', 'wpcc-sign-on' );
		$err = sprintf( $err_format, $this->user_data->email, get_bloginfo( 'name' ) );
		$message .= sprintf( '<p class="message" id="login_error">%s</p>',  );
		return $message;
	}
}

new WPCC_Sign_On;
