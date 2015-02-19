<?php

/**
 * Class helper_plugin_sfauth
 *
 * Represents a single oAuth authenticated SalesForce User
 */
class helper_plugin_sfauth extends DokuWiki_Plugin {

    /** @var string current user to authenticate */
    protected $user = null;

    /** @var array user data for above user */
    protected $userdata = null;

    /** @var array authentication data for above user */
    protected $authdata = null;

    /** @var int salesforce instance to use */
    protected $instance = 1;

    /**
     * Each Instantiated plugin is it's own user
     *
     * @return false
     */
    public function isSingleton() {
        return false;
    }

    /**
     * The local URL that handles all the oAuth flow
     *
     * This is the URL that has to be configured in Salesforce
     *
     * @param int $instance the salesforce configuration instance to use (1 to 3)
     * @return string
     */
    public static function getLoginURL($instance) {
        $instance = (int) $instance;
        if($instance < 1 || $instance > 3) $instance = 1;
        return DOKU_URL . DOKU_SCRIPT . '?do=login&u=sf&p=sf&sf='.$instance;
    }

    /**
     * Get the current user
     *
     * @return bool|string
     */
    public function getUser() {
        if(is_null($this->user)) return false;
        if(is_null($this->userdata)) return false;
        return $this->user;
    }

    /**
     * Get the user's data
     *
     * @return bool|array
     */
    public function getUserData() {
        if(is_null($this->userdata)) return false;
        return $this->userdata;
    }

    /**
     * Initialize the user object by the given user name
     *
     * @param $user
     * @return bool true if the user was found, false otherwise
     */
    public function init_by_user($user) {
        try {
            $this->loadFromFile($user);
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Initialize the user by starting an oAuth flow
     *
     * @param int $instance Salesforce config instance
     * @return bool true if the oAuth flow has completed successfully, false on error
     */
    public function init_by_oauth($instance) {
        global $INPUT;
        $instance = (int) $instance;
        if($instance < 1 || $instance > 3) $instance = 1;
        $this->instance = $instance;

        // login directly from Saleforce
        if($INPUT->get->str('user') && $INPUT->get->str('sessionId')) {
            if($this->oauth_directlogin($INPUT->get->str('user'), $INPUT->get->str('sessionId'), $INPUT->get->str('instance'))) {
                if($this->loadUserDataFromSalesForce()) {
                    if($this->saveToFile()) {
                        msg('Authentication successful', 1);
                        return true;
                    }
                }
            }
            msg('Oops! something went wrong.', -1);
            return false;
        }

        // oAuth step 2: request auth token
        if($INPUT->get->str('code')) {
            if($this->oauth_finish($INPUT->get->str('code'), $instance)) {
                if($this->loadUserDataFromSalesForce()) {

                    if($this->saveToFile()) {
                        msg('Authentication successful', 1);
                        return true;
                    }
                }
            }
            msg('Oops! something went wrong.', -1);
            return false;
        }

        // oAuth step 1: redirect to salesforce
        $this->oauth_start($this->instance);
        return false; // will not be reached
    }

    /**
     * Execute an API call with the current author
     */
    public function apicall($method, $endpoint, $data = array(), $usejson = true) {
        if(!$this->authdata) throw new Exception('No auth data to make API call');

        $json = new JSON(JSON_LOOSE_TYPE);
        $url  = $this->authdata['instance_url'] . '/services/data/v24.0' . $endpoint;

        $http                           = new DokuHTTPClient();
        $http->timeout                  = 30;
        $http->headers['Authorization'] = $this->authdata['access_token'];
        $http->headers['Accept']        = 'application/json';
        $http->headers['X-PrettyPrint'] = '1';

        //$http->debug = 1;

        if($data) {
            if($usejson) {
                $data                          = $json->encode($data);
                $http->headers['Content-Type'] = 'application/json';
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
        if($resp[0]['errorCode'] == 'INVALID_SESSION_ID') {
            if($this->oauth_refresh()) {
                return $this->apicall($method, $endpoint, $data);
            } else {
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
     * Initialize the OAuth process
     *
     * by redirecting the user to the login site
     * @link http://bit.ly/y7WOmy
     */
    protected function oauth_start($instance) {
        global $ID;
        $instance = (int) $instance;
        if($instance < 1 || $instance > 3) $instance = 1;
        $this->instance = $instance;

        $_SESSION['sfauth_redirect'] = $ID; // where wanna go later

        $data = array(
            'response_type' => 'code',
            'client_id'     => $this->getConf('consumer key'),
            'redirect_uri'  => self::getLoginURL($this->instance),
            'display'       => 'page', // may popup
        );

        $url = $this->getConf('auth url') . '/services/oauth2/authorize?' . buildURLparams($data, '&');
        send_redirect($url);
    }

    /**
     * Request an authentication code with the given request token
     *
     * @param string $code request token
     * @param int $instance Salesforce instance to authenticate with
     * @return bool
     */
    protected function oauth_finish($code, $instance) {
        $instance = (int) $instance;
        if($instance < 1 || $instance > 3) $instance = 1;
        $this->instance = $instance;

        /*
         * request the authdata with the code
         */
        $data = array(
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->getIConf('consumer key', $this->instance),
            'client_secret' => $this->getIConf('consumer secret', $this->instance),
            'redirect_uri'  => self::getLoginURL($this->instance)
        );

        $url = $this->getConf('auth url') . '/services/oauth2/token';
        $http                    = new DokuHTTPClient();
        $http->headers['Accept'] = 'application/json';
        $resp                    = $http->post($url, $data);

        if($resp === false) return false;

        $json                 = new JSON(JSON_LOOSE_TYPE);
        $resp                 = $json->decode($resp);
        $resp['access_token'] = 'OAuth ' . $resp['access_token'];

        $this->authdata = $resp;
        return true;
    }

    /**
     * request a new auth key
     */
    protected function oauth_refresh() {
        if(!$this->authdata) throw new Exception('No auth data to refresh oauth token');
        if(!isset($this->authdata['refresh_token'])) {
            return false;
        }
        $data = array(
            'grant_type'    => 'refresh_token',
            'refresh_token' => $this->authdata['refresh_token'],
            'client_id'     => $this->getIConf('consumer key', $this->instance),
            'client_secret' => $this->getIConf('consumer secret', $this->instance)
        );

        $url                     = $this->getConf('auth url') . '/services/oauth2/token?' . buildURLparams($data, '&');
        $http                    = new DokuHTTPClient();
        $http->headers['Accept'] = 'application/json';
        $resp                    = $http->post($url, array());
        if($resp === false) return false;
        $json = new JSON(JSON_LOOSE_TYPE);

        $resp       = $json->decode($resp);
        $this->authdata = $resp;

        return $this->saveToFile();
    }

    /**
     * Does a direct login by setting the given sessionID as access token
     *
     * @param string $user
     * @param string $sessionId
     * @param string $instanceurl
     * @return bool
     */
    protected function oauth_directlogin($user, $sessionId, $instanceurl) {
        $url        = parse_url($instanceurl);
        $this->authdata = array(
            'instance_url' => sprintf('%s://%s', $url['scheme'], $url['host']),
            'access_token' => 'Bearer ' . $sessionId
        );

        $this->user = $user;
        return true;
    }

    /**
     * Load current user's data into memory cache
     *
     * @return bool
     */
    protected function loadUserDataFromSalesForce() {
        global $conf;
        $id = preg_replace('/^.*\//', '', $this->authdata['id']);

        $resp = $this->apicall('GET', '/sobjects/User/' . rawurlencode($id));
        if(!$resp) return false;

        $this->userdata = array(
            'name' => $resp['Name'],
            'mail' => $resp['Email'],
            'grps' => explode(';', $resp['DokuWiki_Groups__c']),
            'sfid' => $resp['Id']
        );

        // add instance as group and default group
        $this->userdata['grps'][] = 'salesforce'.$this->instance;
        $this->userdata['grps'][] = $conf['defaultgroup'];

        $this->userdata['grps'] = array_unique($this->userdata['grps']);
        $this->userdata['grps'] = array_filter($this->userdata['grps']);

        $this->user = $this->transformMailToId($this->userdata['mail']);
        return true;
    }

    /**
     * Transforms a mail to ID
     *
     * @todo put this in the getUser() function
     * @param $mail
     * @return mixed
     */
    protected function transformMailToId($mail) {
        if(!strpos($mail, '@')) {
            return $mail;
        }

        $ownerDomain = $this->getConf('owner domain');
        if(empty($ownerDomain)) {
            return $mail;
        }

        $newMail = preg_replace('/' . preg_quote('@' . $ownerDomain, '/') . '$/i', '', $mail);

        return $newMail;
    }

    /**
     * Load user and auth data from local files
     *
     * @param $user
     * @return bool
     * @throws Exception
     */
    protected function loadFromFile($user) {
        $userdata = getCacheName($user,'.sfuser');
        $authdata = getCacheName($user,'.sfauth');

        if(file_exists($userdata)) {
            $this->userdata = unserialize(io_readFile($userdata, false));
        } else {
            throw new Exception('No such user');
        }

        if(file_exists($authdata)) {
            $this->authdata = unserialize(io_readFile($authdata, false));
            $this->instance = $this->authdata['dokuwiki-instance'];
        } else {
            throw new Exception('No such user');
        }

        $this->user = $user;
        return true;
    }

    /**
     * Store user and auth data to local files
     *
     * @throws Exception
     * @return bool
     */
    protected function saveToFile() {
        if(!$this->user) throw new Exception('No user info to save');

        $this->authdata['dokuwiki-instance'] = $this->instance;

        $userdata = getCacheName($this->user,'.sfuser');
        $authdata = getCacheName($this->user,'.sfauth');
        $ok1 = io_saveFile($userdata, serialize($this->userdata));
        $ok2 = io_saveFile($authdata, serialize($this->authdata));

        return $ok1 && $ok2;
    }

    /**
     * Get a config setting for the specified instance
     *
     * @param $config
     * @param $instance
     * @return mixed
     */
    protected function getIConf($config, $instance) {
        if($instance === 2 || $instance === 3) {
            $postfix = ' '.$instance;
        } else {
            $postfix = '';
        }

        return $this->getConf($config.$postfix);
    }

}