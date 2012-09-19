<?php

require_once DOKU_INC . 'inc/auth/plain.class.php';

class auth_sfauth extends auth_plain {

    private $authurl;
    private $auth = null;
    private $user = '';

    private $salesForceUsers = array();

    public function __construct() {
        parent::auth_plain();
        $this->authurl = DOKU_URL.'doku.php?do=login&u=a';
        $this->user = '';
    }

    private function isSfConfigured() {
        global $conf;
        if (empty($conf['plugin']['sfauth']['consumer key'])) return false;
        if (empty($conf['plugin']['sfauth']['consumer secret'])) return false;
        if (empty($conf['plugin']['sfauth']['auth url'])) return false;
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

        $resp = $this->apicall('GET', '/chatter/users/' . rawurlencode($user));
        if (!$resp) return false;
        return $this->parseUserData($resp);
    }

    private function parseUserData($data) {
        $this->salesForceUsers[$data['Id']] = array(
            'name' => $data['Name'],
            'mail' => $data['Email'],
            'grps' => explode(';', $data['DokuWiki_Groups__c'])
        );
        return $this->salesForceUsers[$data['id']];
    }

    function checkPass(&$user, $pass) {
        if (!empty($pass)) {
            return parent::checkPass($user, $pass);
        }
        if (!$this->checkConfiguration()) return false;

        if ($_GET['code']) {
            if ($this->oauth_finish($_GET['code'])) {
                $resp = $this->apicall('GET', '/chatter/users/me');
                $user = $resp['id'];
                $this->user = $user;
                $resp = $this->apicall('GET', '/sobjects/User/' . rawurlencode($user));
                $this->parseUserData($resp);

                if ($this->save_auth()) {
                    msg('Authentication successful', 1);
                    return true;
                }
            }
            msg('Oops! something went wrong.', -1);
            return false;
        }
        $this->oauth_start();
        return false;
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

        $url = $conf['plugin']['sfauth']['auth url'] . '/services/oauth2/token';

        $http = new DokuHTTPClient();
        $http->headers['Accept'] = 'application/json';
        $resp = $http->post($url, $data);
        if($resp === false) return false;

        $json = new JSON(JSON_LOOSE_TYPE);
        $resp = $json->decode($resp);

        $this->user = $resp['id'];
        $this->auth = $resp;

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
        $data = array(
            'response_type' => 'code',
            'client_id'     => $conf['plugin']['sfauth']['consumer key'],
            'redirect_uri'  => $this->authurl,
            'display'       => 'page', // may popup
        );

        $url = $conf['plugin']['sfauth']['auth url'].'/services/oauth2/authorize?'.buildURLparams($data, '&');
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
        global $conf;
        if(!$this->load_auth()) return false;
        $data = array(
            'grant_type'    => 'refresh_token',
            'refresh_token' => $this->auth['refresh_token'],
            'client_id'     => $conf['plugin']['sfauth']['consumer key'],
            'client_secret' => $conf['plugin']['sfauth']['consumer secret']
        );

        $url = $conf['plugin']['sfauth']['auth url'].'/services/oauth2/token?'.buildURLparams($data, '&');
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
        $http->headers['Authorization'] = 'OAuth '.$this->auth['access_token'];
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
        if(!$http->resp_body) return false;
        $resp = $json->decode($http->resp_body);

        // session expired, request a new one and retry
        if($resp[0]['errorCode'] == 'INVALID_SESSION_ID'){
            if($this->oauth_refresh()){
                return $this->apicall($method,$endpoint,$data);
            }else{
                return false;
            }
        }

        if($http->status < 200 || $http->status > 399) return false;

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
}
