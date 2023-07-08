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
 * Plugin administration pages are defined here.
 *
 * @package     auth_thaid
 * @category    admin
 * @copyright   2023 Taemin <taemin@kku.ac.th>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
require_once(__DIR__."/function.php");

defined('MOODLE_INTERNAL') || die();


if ($ADMIN->fulltree) {
    // TODO: Define actual plugin settings page and add it to the tree - {@link https://docs.moodle.org/dev/Admin_settings}.
    require_once($CFG->libdir . '/authlib.php');

    $settings->add(new admin_setting_configtext("auth_thaid/redirect_uri",get_string('redirect_uri', 'auth_thaid'),get_string('redirect_uri_desc', 'auth_thaid'),getCallbackURI()));

    $settings->add(new admin_setting_configtext('auth_thaid/client_id', get_string('client_id', 'auth_thaid'),
        null, null));

    $settings->add(new admin_setting_configtext('auth_thaid/client_secret', get_string('client_secret', 'auth_thaid'),
        null, null));

    $settings->add(new admin_setting_configtext('auth_thaid/api_key', get_string('api_key', 'auth_thaid'),
        null, null));

//////////////////////////////////////////
    $settings->add(new admin_setting_heading("auth_thaid/field_mapping","Field mapping",null));

    $settings->add(new admin_setting_configcheckbox('auth_thaid/sync', get_string('sync', 'auth_thaid'),
        get_string('sync_detail', 'auth_thaid'), false));

    $settings->add(new admin_setting_description('auth_thaid/username', get_string('username', 'auth_thaid'),
        "<div class='alert alert-info'>pid</div>"));

    $settings->add(new admin_setting_configselect('auth_thaid/firstname', get_string('firstname', 'auth_thaid'),null,"TH",["TH"=>"TH","EN"=>"EN"]));

    $settings->add(new admin_setting_configselect('auth_thaid/lastname', get_string('lastname', 'auth_thaid'),null,"TH",["TH"=>"TH","EN"=>"EN"]));

    $settings->add(new admin_setting_configtext('auth_thaid/button_name', get_string('button_label', 'auth_thaid'),
        null,null));

    $ADMIN->add('auth_thaid', $settings);
}
