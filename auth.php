<?php

class auth_plugin_sfauth extends auth_plugin_authplain {
    /** @var helper_plugin_sfauth */
    protected $hlp = null;

    /**
     * Get user data
     *
     * @param string $user
     * @return array|bool|false
     */
    function getUserData($user) {
        $data = parent::getUserData($user);
        if($data) return $data;

        if(!$this->checkConfiguration()) return false;

        /** @var helper_plugin_sfauth $sfuser */
        $sfuser = plugin_load('helper', 'sfauth');
        if($sfuser->init_by_user($user)) {
            return $sfuser->getUserData();
        }

        return false;
    }

    /**
     * Check given user and password
     *
     * Also initiates the oauth process
     *
     * @param string $user
     * @param string $pass
     * @return bool
     */
    function checkPass(&$user, $pass) {
        global $INPUT;

        if(!$INPUT->has('sf')) {
            return parent::checkPass($user, $pass);
        }
        if(!$this->checkConfiguration()) return false;

        /** @var helper_plugin_sfauth $sfuser */
        $sfuser = plugin_load('helper', 'sfauth');
        if($sfuser->init_by_oauth()) {
            $user = $sfuser->getUser();
            return true;
        }

        return false;
    }

    /**
     * Check if the plugin is completely configured
     *
     * @return bool
     */
    private function isSfConfigured() {
        if(!$this->getConf('consumer key')) return false;
        if(!$this->getConf('consumer secret')) return false;
        if(!$this->getConf('auth url')) return false;
        return true;
    }

    /**
     * Wrap around the config check, emit a warning on first call
     *
     * @return bool
     */
    public function checkConfiguration() {
        if($this->isSfConfigured()) {
            return true;
        }

        static $warningShown = false;

        if(!$warningShown) {
            msg('SalesForce login not configured. Just using plain auth.', 2);
            $warningShown = true;
        }
        return false;
    }



}
