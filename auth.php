<?php

class auth_plugin_sfauth extends auth_plugin_authplain {

    private $authurl;
    public  $auth = null;
    private $user = '';

    private $salesForceUsers = array();

    public function __construct() {
        parent::__construct();

        $this->authurl = DOKU_URL.DOKU_SCRIPT.'?do=login&u=a';
        $this->user = '';
    }

    private function isSfConfigured() {
        if (!$this->getConf('consumer key')) return false;
        if (!$this->getConf('consumer secret')) return false;
        if (!$this->getConf('auth url')) return false;
        return true;
    }

    public function checkConfiguration() {
        if ($this->isSfConfigured()) {
            return true;
        }

        static $warningShown = false;

        if (!$warningShown) {
            msg('SalesForce login not configured. Just using plain auth.', 2);
            $warningShown = true;
        }
        return false;
    }

    function getUserData($user) {
        $data = parent::getUserData($user);
        if ($data) return $data;

        if (!$this->checkConfiguration()) return false;
        if (array_key_exists($user, $this->salesForceUsers)) {
            return $this->salesForceUsers[$user];
        }
        return false;
    }

    private function parseUserData($data) {
        $id = $this->transformMailToId($data['Email']);
        $this->salesForceUsers[$id] = array(
            'name' => $data['Name'],
            'mail' => $data['Email'],
            'grps' => explode(';', $data['DokuWiki_Groups__c']),
            'sfid' => $data['Id']
        );
        return $this->salesForceUsers[$id];
    }

    public function transformMailToId($mail) {
        if (!strpos($mail, '@')) {
            return $mail;
        }

        $ownerDomain = $this->getConf('owner domain');
        if (empty($ownerDomain)) {
            return $mail;
        }

        $newMail = preg_replace('/' . preg_quote('@' . $ownerDomain, '/') . '$/i', '', $mail);

        return $newMail;
    }

    function checkPass(&$user, $pass) {
        global $INPUT;

        if (!$INPUT->has('sfauth')) {
            return parent::checkPass($user, $pass);
        }
        if (!$this->checkConfiguration()) return false;



        if ($INPUT->get->str('user') && $INPUT->get->str('sessionId')) {
            if ($this->oauth_finish_session($INPUT->get->str('user'), $INPUT->get->str('sessionId'), $INPUT->get->str('instance'))) {
                if ($this->prepareSalesForceSession()) {
                    if ($this->save_auth()) {
                        msg('Authentication successful', 1);
                        $user = $this->user;
                        return true;
                    }
                }
            }
            msg('Oops! something went wrong.', -1);
            return false;
        }

        if ($INPUT->get->str('code')) {
            if ($this->oauth_finish($INPUT->get->str('code'))) {
                if ($this->prepareSalesForceSession()) {

                    if ($this->save_auth()) {
                        msg('Authentication successful', 1);
                        $user = $this->user;
                        return true;
                    }
                }
            }
            msg('Oops! something went wrong.', -1);
            return false;
        }
        $this->oauth_start();
        return false;
    }

    private function prepareSalesForceSession() {
        $resp = $this->apicall('GET', '/chatter/users/me');
        if (!$resp) return false;
        $id = $resp['id'];
        $this->user = $this->transformMailToId($resp['email']);
        $resp = $this->apicall('GET', '/sobjects/User/' . rawurlencode($id));
        if (!$resp) return false;
        $this->parseUserData($resp);
        return true;
    }

    public function oauth_finish($code){
        global $conf;


        $data = array(
            'code'       => $code,
            'grant_type' => 'authorization_code',
            'client_id'     => $conf['plugin']['sfauth']['consumer key'],
            'client_secret' => $conf['plugin']['sfauth']['consumer secret'],
            'redirect_uri'  => $this->authurl
        );

        $url = $this->getConf('auth url') . '/services/oauth2/token';

        $http = new DokuHTTPClient();
        $http->headers['Accept'] = 'application/json';
        $resp = $http->post($url, $data);
        if($resp === false) return false;

        $json = new JSON(JSON_LOOSE_TYPE);
        $resp = $json->decode($resp);
        $resp['access_token'] = 'OAuth '.$resp['access_token'];

        $this->user = $resp['id'];
        $this->auth = $resp;

        return true;
    }

    public function oauth_finish_session($user, $sessionId, $instance){
        $url = parse_url($instance);
        $this->auth = array(
            'instance_url' => sprintf('%s://%s', $url['scheme'], $url['host']),
            'access_token' => 'Bearer ' . $sessionId
        );

        $this->user = $user;
        return true;
    }


    /**
     * Initialize the OAuth process
     *
     * by redirecting the user to the login site
     * @link http://bit.ly/y7WOmy
     */
    public function oauth_start(){
        global $conf;

        if (isset($_REQUEST['id'])) $_SESSION['sfauth_redirect'] = $_REQUEST['id'];

        $data = array(
            'response_type' => 'code',
            'client_id'     => $conf['plugin']['sfauth']['consumer key'],
            'redirect_uri'  => $this->authurl,
            'display'       => 'page', // may popup
        );

        $url = $this->getConf('auth url').'/services/oauth2/authorize?'.buildURLparams($data, '&');
        send_redirect($url);
    }

    /**
     * Saves the access info
     */
    public function save_auth(){
        if(!$this->user) return false;
        if(is_null($this->auth)) return false;

        $tokenfile = getCacheName($this->user,'.chatter-auth');
        return io_saveFile($tokenfile, serialize($this->auth));
    }

    /**
     * request a new auth key
     */
    public function oauth_refresh(){
        if(!$this->load_auth()) return false;
        if (!isset($this->auth['refresh_token'])) {
            return false;
        }
        $data = array(
            'grant_type'    => 'refresh_token',
            'refresh_token' => $this->auth['refresh_token'],
            'client_id'     => $this->getConf('consumer key'),
            'client_secret' => $this->getConf('consumer secret')
        );

        $url = $this->getConf('auth url').'/services/oauth2/token?'.buildURLparams($data, '&');
        $http = new DokuHTTPClient();
        $http->headers['Accept'] = 'application/json';
        $resp = $http->post($url,array());
        if($resp === false) return false;
        $json = new JSON(JSON_LOOSE_TYPE);

        $resp = $json->decode($resp);
        $this->auth = $resp;

        return $this->save_auth();
    }

    /**
     * Execute an API call with the current author
     */
    public function apicall($method,$endpoint,$data=array(),$usejson=true){
        if ($this->user === '') {
            $this->user = $_SERVER['REMOTE_USER'];
        }
        if(!$this->load_auth()) return false;

        $json = new JSON(JSON_LOOSE_TYPE);
        $url   = $this->auth['instance_url'].'/services/data/v24.0'.$endpoint;

        $http = new DokuHTTPClient();
        $http->timeout = 30;
        $http->headers['Authorization'] = $this->auth['access_token'];
        $http->headers['Accept']        = 'application/json';
        $http->headers['X-PrettyPrint'] = '1';

#        $http->debug = 1;

        if($data){
            if($usejson){
                $data = $json->encode($data);
                $http->headers['Content-Type']  = 'application/json';
            }
            // else default to standard POST encoding
        }
        $http->sendRequest($url, $data, $method);
        if(!$http->resp_body) {
            dbglog('err call' . print_r($http, true), 'sfauth');
            return false;
        }
        $resp = $json->decode($http->resp_body);

        // session expired, request a new one and retry
        if($resp[0]['errorCode'] == 'INVALID_SESSION_ID'){
            if($this->oauth_refresh()){
                return $this->apicall($method,$endpoint,$data);
            }else{
                return false;
            }
        }

        if($http->status < 200 || $http->status > 399) {
            dbglog('err call' . print_r($http, true), 'sfauth');
            return false;
        }

        return $resp;
    }

    /**
     * Loads the access info
     */
    public function load_auth(){
        if(!$this->user) return false;
        if(!is_null($this->auth)) return true;
        $tokenfile = getCacheName($this->user,'.chatter-auth');

        if(file_exists($tokenfile)){
            $this->auth = unserialize(io_readFile($tokenfile,false));
            return true;
        }else{
            return false;
        }
    }

    public function isAuthenticated() {
        return !is_null($this->auth);
    }
}
