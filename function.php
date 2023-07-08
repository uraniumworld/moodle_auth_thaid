<?php

require_once(__DIR__."/../../config.php");
require_once(__DIR__."/vendor/autoload.php");
global $CFG;
require_once($CFG->dirroot . '/user/lib.php');
use Firebase\JWT\JWT;

function getCallbackURI(){
    global $CFG;
    return $CFG->wwwroot."/auth/thaid/callback.php";
}

function getCredentials(): string
{
    $client_id=get_config('auth_thaid',"client_id");
    $client_secret=get_config('auth_thaid',"client_secret");
    return base64_encode("{$client_id}:{$client_secret}");
}

function completeLogin($userId){
    global $CFG,$SESSION;
    $jwt_token = JWT::encode([
        "user_id"=>$userId,
        'iat' => time(),
        "exp"=>time()+60,
    ],getCredentials(),"HS256");
    redirect("{$CFG->wwwroot}/login?thaid=1&token={$jwt_token}");
}

function updateUserProfile($uid,$firstname,$lastname){
    global $DB;
    $user = $DB->get_record('user', array('id' => $uid), '*');
    if($user){
        $user->firstname=$firstname;
        $user->lastname=$lastname;
    }
    $DB->update_record("user",$user);
}

function createUser($profile,$email){
    $user = new stdClass();
    $user->username = $profile->pid;
    $user->password = hash_internal_user_password("NO_LOGIN",true);
    $user->firstname = $profile->firstname;
    $user->lastname = $profile->lastname;
    $user->email = $email;
    $user->auth = 'thaid';
    $user->idnumber = $profile->pid;
    $user->lang = 'en';
    $user->timezone = 'Asia/Bangkok';
    $user->confirmed = 1;
    $user->mnethostid = 1;
    return user_create_user($user);
}