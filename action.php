<?php
/**
 * DokuWiki Plugin sfauth (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Dominik Eckelmann, Andreas Gohr
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

if(!defined('DOKU_LF')) define('DOKU_LF', "\n");
if(!defined('DOKU_TAB')) define('DOKU_TAB', "\t");
if(!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN', DOKU_INC . 'lib/plugins/');

require_once DOKU_PLUGIN . 'action.php';

class action_plugin_sfauth extends DokuWiki_Action_Plugin {

    public function register(Doku_Event_Handler $controller) {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'AFTER', $this, 'handle_html_loginform_output');
        $controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'handle_login');
    }

    public function handle_html_loginform_output(Doku_Event &$event, $param) {
        global $auth;
        if(!($auth instanceof auth_plugin_sfauth)) {
            return;
        }

        $this->displayLogin();
    }

    /**
     * Displays the Salesforce Login Button
     *
     * Note: We always use the main instance to start the oauth workflow because it doesn't matter. Salesforce
     * will use the redirect URI configured in the instance of the user that logged in and that will contain the
     * correct instance number for all subsequent API calls. this way we only need one login button
     */
    protected function displayLogin() {
        global $ID;
        echo '<div class="sfauth">';
        if($this->getConf('consumer key')) {
            echo '<a href="'.wl($ID, array('do' => 'login', 'u' => 'sf', 'p' => 'sf', 'sf' => '1')).'" class="sf">';
            echo $this->getLang('login');
            echo '</a> ';
        }
        echo '</div>';
    }

    /**
     * Redirect to the page that initially started the auth process
     *
     * @param Doku_Event $event
     * @param $param
     */
    public function handle_login(Doku_Event &$event, $param) {
        if($_SERVER['REMOTE_USER'] && isset($_SESSION['sfauth_id'])) {
            $id = $_SESSION['sfauth_id'];
            unset($_SESSION['sfauth_id']);
            send_redirect(wl($id, '', true, '&'));
        }
    }
}

// vim:ts=4:sw=4:et:
