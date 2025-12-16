<?php
/**
 * Plugin Name: JetForm Register - Approve 
 * Description: JetFormBuilder addon to automatically send a link to delete or approve a new user
 * Version: 2.1
 * Author: Angelo Marra
 * License: GPL2
 */

if (!defined('ABSPATH')) exit;

/* ---------------------------
 * ADMIN GUI
 * --------------------------- */
add_action('admin_menu', 'rctl_add_admin_menu');
function rctl_add_admin_menu() {
    add_options_page(
        'JetForm Register - Approve',
        'JetForm Approve',
        'manage_options',
        'rctl-settings',
        'rctl_settings_page'
    );
}

add_action('admin_init', 'rctl_register_settings');
function rctl_register_settings() {
    register_setting('rctl_settings_group', 'rctl_default_role', array(
        'type' => 'string',
        'default' => 'customer',
        'sanitize_callback' => 'sanitize_key'
    ));
    
    register_setting('rctl_settings_group', 'rctl_token_hours', array(
        'type' => 'integer',
        'default' => 24,
        'sanitize_callback' => 'absint'
    ));
}

function rctl_settings_page() {
    if (!current_user_can('manage_options')) {
        return;
    }
    
    // Save settings if form was submitted
    if (isset($_POST['rctl_settings_save'])) {
        check_admin_referer('rctl_settings_action', 'rctl_settings_nonce');
        update_option('rctl_default_role', sanitize_key($_POST['rctl_default_role']));
        update_option('rctl_token_hours', absint($_POST['rctl_token_hours']));
        echo '<div class="notice notice-success is-dismissible"><p>Settings saved successfully!</p></div>';
    }
    
    $current_role = get_option('rctl_default_role', 'customer');
    $current_hours = get_option('rctl_token_hours', 24);
    
    // Get all available roles
    $roles = wp_roles()->roles;
    ?>
    <div class="wrap">
        <h1>JetForm Register - Approve</h1>
        <p>Configure the behavior of approval links sent to the administrator.</p>
        
        <form method="post" action="">
            <?php wp_nonce_field('rctl_settings_action', 'rctl_settings_nonce'); ?>
            
            <table class="form-table" role="presentation">
                <tbody>
                    <tr>
                        <th scope="row">
                            <label for="rctl_default_role">Default user role</label>
                        </th>
                        <td>
                            <select name="rctl_default_role" id="rctl_default_role" class="regular-text">
                                <?php foreach ($roles as $role_key => $role_data): ?>
                                    <option value="<?php echo esc_attr($role_key); ?>" <?php selected($current_role, $role_key); ?>>
                                        <?php echo esc_html($role_data['name']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">
                                Role that will be assigned to the user when admin clicks the approval link.
                            </p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">
                            <label for="rctl_token_hours">Token duration (hours)</label>
                        </th>
                        <td>
                            <input type="number" name="rctl_token_hours" id="rctl_token_hours" 
                                   value="<?php echo esc_attr($current_hours); ?>" 
                                   class="regular-text" min="1" max="720" step="1">
                            <p class="description">
                                Number of hours the approval/deletion link remains valid (1-720 hours).
                            </p>
                        </td>
                    </tr>
                </tbody>
            </table>
            
            <?php submit_button('Save Settings', 'primary', 'rctl_settings_save'); ?>
        </form>
        
        <hr>
        
        <h2>How to use the plugin</h2>
        <div style="background: #fff; border-left: 4px solid #2271b1; padding: 15px; margin-top: 20px;">
            <h3>Placeholders for JetFormBuilder emails:</h3>
            <p><strong>Approval link:</strong></p>
            <code>::RCTL_LINK::email@example.com|Link text::</code>
            <p style="margin-top: 10px;"><strong>Deletion link:</strong></p>
            <code>::RCTL_DELETE_LINK::email@example.com|Link text::</code>
            <p style="margin-top: 15px;"><em>Note: you can use JetFormBuilder placeholders for email, e.g.: ::RCTL_LINK::%user_email%::</em></p>
        </div>
    </div>
    <?php
}

/* ---------------------------
 * 1) Generate token on user_register
 * --------------------------- */
add_action('user_register', function($user_id){
    $target_role = get_option('rctl_default_role', 'customer');
    rctl_generate_and_store_token($user_id, $target_role);
});

/* ---------------------------
 * 2) Function to generate token and save in usermeta
 * --------------------------- */
function rctl_generate_and_store_token($user_id, $target_role, $expires_in_seconds = null){
    $allowed_roles = apply_filters('rctl_allowed_roles', array_keys(wp_roles()->roles));
    if(!in_array($target_role, $allowed_roles, true)) {
        return new WP_Error('role_not_allowed', 'Target role not allowed');
    }

    if (is_null($expires_in_seconds)) {
        $hours = get_option('rctl_token_hours', 24);
        $expires_in_seconds = intval($hours) * 3600;
    } else {
        $expires_in_seconds = intval($expires_in_seconds);
    }
    
    $token = wp_generate_password(48, false, false);
    $expires = time() + $expires_in_seconds;

    update_user_meta($user_id, '_rctl_token', $token);
    update_user_meta($user_id, '_rctl_token_expires', $expires);
    update_user_meta($user_id, '_rctl_target_role', $target_role);

    return array('token' => $token, 'expires' => $expires, 'role' => $target_role);
}

/* ---------------------------
 * 3) Shortcode [rctl_role_link_force]
 * --------------------------- */
add_shortcode('rctl_role_link_force', function($atts){
    $atts = shortcode_atts(array(
        'uid' => '',
        'email' => '',
        'role' => '',
        'text' => 'Approve registration',
        'class' => '',
    ), $atts, 'rctl_role_link_force');

    $uid = 0;
    if(!empty($atts['uid'])) {
        $uid = intval($atts['uid']);
    } elseif(!empty($atts['email'])){
        $user = get_user_by('email', sanitize_email($atts['email']));
        if($user) $uid = $user->ID;
    }
    if(!$uid) return '<!-- rctl_role_link_force: user not found -->';

    // If no role is specified, use the one from settings
    $role = !empty($atts['role']) ? sanitize_key($atts['role']) : get_option('rctl_default_role', 'customer');
    
    $res = rctl_generate_and_store_token($uid, $role);
    if(is_wp_error($res)) return '<!-- rctl_role_link_force: error generating token -->';

    $args = array('uid' => $uid, 't' => rawurlencode($res['token']));
    $url = add_query_arg($args, rest_url('rctl/v1/role-change'));
    $a_class = $atts['class'] ? ' class="'.esc_attr($atts['class']).'"' : '';
    $anchor = '<a href="'.esc_url($url).'"'.$a_class.'>'.esc_html($atts['text']).'</a>';
    $plain = esc_url_raw($url);

    return $anchor.'<br/><small>If the click doesn\'t work, copy/paste this link in your browser:<br/>'.esc_html($plain).'</small>';
});

/* ---------------------------
 * 4) REST endpoint for role change
 * --------------------------- */
add_action('rest_api_init', function(){
    register_rest_route('rctl/v1', '/role-change', array(
        'methods' => 'GET',
        'callback' => 'rctl_rest_handle_role_change',
        'args' => array(
            'uid' => array('required' => true, 'sanitize_callback' => 'absint'),
            't' => array('required' => true, 'sanitize_callback' => 'sanitize_text_field')
        ),
        'permission_callback' => '__return_true'
    ));
});

function rctl_rest_handle_role_change($request){
    $uid = $request->get_param('uid');
    $token = html_entity_decode(urldecode($request->get_param('t')));

    $saved_token = get_user_meta($uid, '_rctl_token', true);
    $expires = intval(get_user_meta($uid, '_rctl_token_expires', true));
    $target_role = get_user_meta($uid, '_rctl_target_role', true);

    if(!$saved_token || !hash_equals($saved_token, $token) || time() > $expires) {
        return new WP_Error('invalid_token', 'Invalid or expired token', array('status' => 403));
    }

    $user = get_user_by('id', $uid);
    if(!$user) return new WP_Error('user_not_found', 'User not found', array('status' => 404));

    $user->set_role($target_role);

    delete_user_meta($uid, '_rctl_token');
    delete_user_meta($uid, '_rctl_token_expires');
    delete_user_meta($uid, '_rctl_target_role');

    $redirect = add_query_arg('rctl_confirm', '1', home_url('/'));
    wp_safe_redirect($redirect); 
    exit;
}

/* browser alert for role change */
add_action('wp_footer', function(){
    if(isset($_GET['rctl_confirm']) && $_GET['rctl_confirm'] == '1'){
        echo "<script>alert('Role changed successfully!');</script>";
    }
});

/* ---------------------------
 * 5) Shortcode / placeholder for account deletion
 * --------------------------- */
add_shortcode('rctl_delete_user_link', function($atts){
    $atts = shortcode_atts(array(
        'uid' => '',
        'email' => '',
        'text' => 'Delete account',
        'class' => ''
    ), $atts, 'rctl_delete_user_link');

    $uid = 0;
    if(!empty($atts['uid'])) {
        $uid = intval($atts['uid']);
    } elseif(!empty($atts['email'])){
        $user = get_user_by('email', sanitize_email($atts['email']));
        if($user) $uid = $user->ID;
    }
    if(!$uid) return '<!-- rctl_delete_user_link: user not found -->';

    $token = wp_generate_password(48, false, false);
    
    // Use configured duration for deletion token as well
    $hours = get_option('rctl_token_hours', 24);
    $expires = time() + (intval($hours) * 3600);
    
    update_user_meta($uid, '_rctl_delete_token', $token);
    update_user_meta($uid, '_rctl_delete_token_expires', $expires);

    $args = array('uid' => $uid, 't' => rawurlencode($token));
    $url = add_query_arg($args, rest_url('rctl/v1/delete-user'));
    $a_class = $atts['class'] ? ' class="'.esc_attr($atts['class']).'"' : '';

    return '<a href="'.esc_url($url).'"'.$a_class.'>'.esc_html($atts['text']).'</a>';
});

/* ---------------------------
 * 6) REST endpoint for account deletion
 * --------------------------- */
add_action('rest_api_init', function(){
    register_rest_route('rctl/v1', '/delete-user', array(
        'methods' => 'GET',
        'callback' => 'rctl_rest_handle_delete_user',
        'args' => array(
            'uid' => array('required' => true, 'sanitize_callback' => 'absint'),
            't' => array('required' => true, 'sanitize_callback' => 'sanitize_text_field')
        ),
        'permission_callback' => '__return_true'
    ));
});

function rctl_rest_handle_delete_user($request){
    $uid = $request->get_param('uid');
    $token = html_entity_decode(urldecode($request->get_param('t')));
    $saved_token = get_user_meta($uid, '_rctl_delete_token', true);
    $expires = intval(get_user_meta($uid, '_rctl_delete_token_expires', true));

    if(!$saved_token || !hash_equals($saved_token, $token) || time() > $expires) {
        return new WP_Error('invalid_token', 'Invalid or expired token', array('status' => 403));
    }

    $user = get_user_by('id', $uid);
    if(!$user) return new WP_Error('user_not_found', 'User not found', array('status' => 404));

    require_once(ABSPATH.'wp-admin/includes/user.php');
    wp_delete_user($uid);

    $redirect = add_query_arg('rctl_deleted', '1', home_url('/'));
    wp_safe_redirect($redirect); 
    exit;
}

/* browser alert for account deletion */
add_action('wp_footer', function(){
    if(isset($_GET['rctl_deleted']) && $_GET['rctl_deleted'] == '1'){
        echo "<script>alert('User deleted successfully!');</script>";
    }
});

/* ---------------------------
 * 7) JetFormBuilder placeholder: Approve role + Delete account
 * --------------------------- */
add_filter('wp_mail', 'rctl_wp_mail_replace_placeholders_final');
function rctl_wp_mail_replace_placeholders_final($mail){
    if(empty($mail['message'])) return $mail;
    $body = $mail['message'];

    // Approve role
    if(preg_match_all('/::RCTL_LINK::([^\s\|<]+)(?:\|([^\n<]+))?/', $body, $matches, PREG_SET_ORDER)){
        foreach($matches as $match){
            $email = trim($match[1]);
            $link_text = isset($match[2]) ? trim($match[2]) : 'Approve registration';
            $user = get_user_by('email', $email);
            if(!$user){
                $body = str_replace($match[0], '[user not found]', $body); 
                continue;
            }
            
            $role = get_option('rctl_default_role', 'customer');
            $res = rctl_generate_and_store_token($user->ID, $role);
            $args = array('uid' => $user->ID, 't' => rawurlencode($res['token']));
            $url = add_query_arg($args, rest_url('rctl/v1/role-change'));
            $anchor = '<a href="'.esc_url($url).'">'.esc_html($link_text).'</a>';
            $plain_url = esc_url_raw($url);
            $body = str_replace($match[0], $anchor.'<br/><small>Copy/paste if needed: '.esc_html($plain_url).'</small>', $body);
        }
    }

    // Delete account
    if(preg_match_all('/::RCTL_DELETE_LINK::([^\s\|<]+)(?:\|([^\n<]+))?/', $body, $matches, PREG_SET_ORDER)){
        foreach($matches as $match){
            $email = trim($match[1]);
            $link_text = isset($match[2]) ? trim($match[2]) : 'Delete account';
            $user = get_user_by('email', $email);
            if(!$user){
                $body = str_replace($match[0], '[user not found]', $body); 
                continue;
            }
            
            $token = wp_generate_password(48, false, false);
            $hours = get_option('rctl_token_hours', 24);
            $expires = time() + (intval($hours) * 3600);
            
            update_user_meta($user->ID, '_rctl_delete_token', $token);
            update_user_meta($user->ID, '_rctl_delete_token_expires', $expires);
            $args = array('uid' => $user->ID, 't' => rawurlencode($token));
            $url = add_query_arg($args, rest_url('rctl/v1/delete-user'));
            $anchor = '<a href="'.esc_url($url).'">'.esc_html($link_text).'</a>';
            $plain_url = esc_url_raw($url);
            $body = str_replace($match[0], $anchor.'<br/><small>Copy/paste if needed: '.esc_html($plain_url).'</small>', $body);
        }
    }

    $mail['message'] = $body;
    return $mail;
}