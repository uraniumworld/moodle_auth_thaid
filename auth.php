<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Authentication class for thaid is defined here.
 *
 * @package     auth_thaid
 * @copyright   2023 Taemin <taemin@kku.ac.th>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/authlib.php');
require_once(__DIR__."/vendor/autoload.php");
require_once(__DIR__."/function.php");
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
// For further information about authentication plugins please read
// https://docs.moodle.org/dev/Authentication_plugins.
//
// The base class auth_plugin_base is located at /lib/authlib.php.
// Override functions as needed.

/**
 * Authentication class for thaid.
 */
class auth_plugin_thaid extends auth_plugin_base
{

    /**
     * Set the properties of the instance.
     */
    public function __construct()
    {
        $this->authtype = 'thaid';
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password)
    {
        global $CFG, $DB;

        // Validate the login by using the Moodle user table.
        // Remove if a different authentication method is desired.
        $user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id));

        // User does not exist.
        if (!$user) {
            return false;
        }

        return validate_internal_user_password($user, $password);
    }

    public function pre_loginpage_hook()
    {
        $this->loginpage_hook();
    }
    public function loginpage_hook()
    {
        global $CFG,$PAGE,$SESSION,$USER,$DB;
        $btnDefault = 'Login ด้วย <img style="height:23px;width:23px;border: 1px solid #b1b1b1;" src="data:image/png;base64,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"/>';
        $btnName=get_config('auth_thaid',"button_name");
        if(!$btnName)$btnName=$btnDefault;
        $js="
        let btnLogin = document.getElementById('loginbtn');
        if(btnLogin){
            let btnThaid = document.createElement('button');
            btnThaid.innerHTML = '{$btnName}';
            btnThaid.style='margin-left:5px;margin-right:5px';
            btnThaid.className='btn btn-primary btn-lg bg-dark2';
            btnThaid.onclick = function(e){
                e.preventDefault();
                let authLink = '{$CFG->wwwroot}/auth/thaid/taemin.php?action=auth';
                document.location.href=authLink;
            }
            btnLogin.after(btnThaid);
        }
        ";
        $PAGE->requires->js_init_call($js,null,true);
        $PAGE->requires->css('/auth/thaid/thaid.css');
        if(@$_GET["thaid"]==1 && isset($_GET["token"])){
            $token = $_GET["token"];
            $decoded = JWT::decode($token,new Key(getCredentials(), 'HS256'));
            $user = $DB->get_record('user', array('id' => $decoded->user_id), '*');
            complete_user_login($user);
            $USER->loggedin = true;
            $USER->site = $CFG->wwwroot;
            set_moodle_cookie($USER->username);

            $wantsurl = core_login_get_return_url();
            if ( qualified_me() !== false && qualified_me() !== $wantsurl ) {
                unset($SESSION->wantsurl);
                redirect($wantsurl);
                exit;
            }
        }
    }

    public function thaid_login_complete($attributes) {
        global $CFG, $USER, $SESSION;
    }
}
