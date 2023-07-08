<?php
require_once "./vendor/autoload.php";
require_once("../../config.php");
require_once("./function.php");
use Firebase\JWT\JWT;

global $CFG,$SESSION,$DB;
$code=$_GET["code"];
$state=$_GET["state"];
if($SESSION->thaid_state != $state){
    throw new Exception("Authentication state not match.");
}
$token_uri = "https://imauth.bora.dopa.go.th/api/v2/oauth2/token/";
$redirect_uri=getCallbackURI();
$client_id=get_config('auth_thaid',"client_id");
$client_secret=get_config('auth_thaid',"client_secret");
$api_key=get_config('auth_thaid',"api_key");
$firstname_lang=get_config("auth_thaid","firstname");
$lastname_lang=get_config("auth_thaid","lastname");
$redirect_uri=get_config("auth_thaid","redirect_uri");
$firstname="given_name";
$lastname="family_name";
if($firstname_lang=="EN"){
    $firstname=$firstname."_en";
}
if($lastname_lang=="EN"){
    $lastname=$lastname."_en";
}
$credentials = getCredentials();
$curl = curl_init();
$str="grant_type=authorization_code&code={$code}&redirect_uri={$redirect_uri}&state={$state}";
curl_setopt($curl, CURLOPT_URL, $token_uri);
curl_setopt($curl, CURLOPT_HTTPHEADER, [
    "Content-type: application/x-www-form-urlencoded",
    "Authorization: Basic {$credentials}"
]);
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_POSTFIELDS, $str);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($curl);
curl_close($curl);
$jsonData=json_decode($response, true);
$profile=[
    "pid"=>$jsonData["pid"],
    "firstname"=>$jsonData[$firstname],
    "lastname"=>$jsonData[$lastname],
    'iat' => time(),
    "exp"=>time()+900,
];
$token = JWT::encode($profile,$credentials,"HS256");
$user_with_username = $DB->get_record('user', array('username' => $jsonData["pid"]), '*');
if(!empty($user_with_username)){
    updateUserProfile($user_with_username->id,$profile["firstname"],$profile["lastname"]);
    completeLogin($user_with_username->id);
}else{
    $sync=get_config("auth_thaid","sync");
    $user_with_idnumber = $DB->get_record('user', array('idnumber' => $jsonData["pid"]), '*');
    if($sync && !empty($user_with_idnumber)){
        updateUserProfile($user_with_idnumber->id,$profile["firstname"],$profile["lastname"]);
        completeLogin($user_with_idnumber->id);
    }else{
        redirect("{$CFG->wwwroot}/auth/thaid/taemin.php?action=confirm&token={$token}&state={$state}");
    }
}
