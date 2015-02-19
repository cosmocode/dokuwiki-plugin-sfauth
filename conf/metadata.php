<?php

class setting_plugin_sfauth extends setting {
    public $_instance = 1;

    function update($input) {
        return true;
    }

    public function html(&$plugin, $echo = false) {
        $key   = htmlspecialchars($this->_key);
        $value = helper_plugin_sfauth::getLoginURL($this->_instance);

        $label = '<label for="config___'.$key.'">'.$this->prompt($plugin).'</label>';
        $input = '<div><code>'.$value.'</code></div>';
        return array($label, $input);
    }
}


$meta['auth url']          = array('multichoice', '_choices' => array('https://test.salesfoce.com', 'https://login.salesforce.com'));
$meta['owner domain']      = array('string');

$meta['callback url']      = array('plugin_sfauth', '_instance' => 1);
$meta['consumer key']      = array('string');
$meta['consumer secret']   = array('password');

$meta['callback url 2']    = array('plugin_sfauth', '_instance' => 2);
$meta['consumer key 2']    = array('string');
$meta['consumer secret 2'] = array('password');

$meta['callback url 3']    = array('plugin_sfauth', '_instance' => 3);
$meta['consumer key 3']    = array('string');
$meta['consumer secret 3'] = array('password');
