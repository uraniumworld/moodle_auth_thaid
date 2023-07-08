<?php
require_once "./vendor/autoload.php";
require_once "../../config.php";
require_once "./function.php";
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
global $CFG,$SESSION,$PAGE,$OUTPUT,$DB;
$action=@$_GET["action"]??"";
$client_id=get_config("auth_thaid","client_id");
$client_secret=get_config("auth_thaid","client_secret");
$sync=get_config("auth_thaid","sync");
$firstname_lang=get_config("auth_thaid","firstname");
$lastname_lang=get_config("auth_thaid","lastname");
$redirect_uri=get_config("auth_thaid","redirect_uri");

if($action=="auth"){
    $api_key=get_config("auth_thaid","api_key");
    $en="";
    $firstname_lang=="EN"?$firstname_lang="_en":$firstname_lang="";
    $lastname_lang=="EN"?$lastname_lang="_en":$lastname_lang="";
    $scopes="pid,given_name{$firstname_lang},family_name{$lastname_lang}";
    $scopes=str_replace(",","%20",$scopes);
    $state='0'.rand(100000,999999);
    $SESSION->thaid_state=$state;
    $url = "https://imauth.bora.dopa.go.th/api/v2/oauth2/auth/?redirect_uri={$redirect_uri}&response_type=code&client_id={$client_id}&scope={$scopes}&state={$state}";
    echo "<a href=\"{$url}\">{$url}</a>";
    redirect($url);
}else if($action=="confirm"){
    if(isset($_GET["token"])){
        $jwt_token = @$_GET["token"];
        $profile = JWT::decode($jwt_token,new Key(getCredentials(), 'HS256'));
        if($profile->exp<=time() || empty($profile->pid) || empty($profile->firstname) || empty($profile->lastname)){
            throw new Exception('Token expired');
        }
        $PAGE->set_title("Confirm your data");
        echo $OUTPUT->header();
        $email="";
        $error="";
        $loginPass=false;
        $user_with_username = $DB->get_record('user', array('username' => $profile->pid), '*');
        $user_with_idnumber = $DB->get_record('user', array('idnumber' => $profile->pid), '*');
        $pattern = '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/';
        $user_with_email=null;
        if(isset($_POST["email"])){
            $email=$_POST["email"];
            $isEmail = preg_match($pattern,$email);
            if(!$email || !$isEmail){
                $error="<div class='alert alert-danger mt-1'>Please fill your email address.</div>";
            }else{
                $user_with_email = $DB->get_record('user', array('email' => $email), '*');
                if(!empty($user_with_email)){
                    $error="<div class='alert alert-danger mt-1'>Email is already registered.</div>";
                }else{
                    $loginPass=true;
                }
            }
         }
        if(!empty($user_with_username)){
            updateUserProfile($user_with_username->id,$profile->firstname,$profile->lastname);
            completeLogin($user_with_username->id);
        }elseif($sync && !empty($user_with_idnumber)){
            updateUserProfile($user_with_username->id,$profile->firstname,$profile->lastname);
            completeLogin($user_with_username->id);
        }else{
            if($loginPass){
                $uid = createUser($profile,$email);
                completeLogin($uid);
            }
        }
        echo "
<div class='card card-primary'>
    <div class='card-header'>
        <div class='card-text'>Confirm your data</div>
    </div>
    <form action='' method='post'>
        <div class='card-body'>
            <div class='form-group'>
                <label class='form-label'>Confirm your email</label>
                <input type='text' name='email' class='form-control' value='{$email}'/>
                {$error}
            </div>
            <hr/>
            <div class='form-group'>
                <label class='form-label'>Identifier number</label>
                <input type='text' class='form-control' readonly value='{$profile->pid}'/>
            </div>
            <div class='form-group'>
                <label class='form-label'>First name</label>
                <input type='text' class='form-control' readonly value='{$profile->firstname}'/>
            </div>
            <div class='form-group'>
                <label class='form-label'>Last name</label>
                <input type='text' class='form-control' readonly value='{$profile->lastname}'/>
            </div>
            <div class='form-group'>
                <div style='display: flex;justify-content:center'>
                    <button type='submit' class='btn btn-primary'>Submit</button>
                </div>
            </div>
        </div>
    </form>
</div>
        ";
        echo $OUTPUT->footer();
    }
}
