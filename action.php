<?php
/**
 * DokuWiki Plugin sfauth (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Dominik Eckelmann, Andreas Gohr
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();

if (!defined('DOKU_LF')) define('DOKU_LF', "\n");
if (!defined('DOKU_TAB')) define('DOKU_TAB', "\t");
if (!defined('DOKU_PLUGIN')) define('DOKU_PLUGIN',DOKU_INC.'lib/plugins/');

require_once DOKU_PLUGIN.'action.php';

class action_plugin_sfauth extends DokuWiki_Action_Plugin {

    public function register(Doku_Event_Handler &$controller) {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'AFTER', $this, 'handle_html_loginform_output');
        $controller->register_hook('ACTION_HEADERS_SEND', 'AFTER', $this, 'handle_login');

        if ($this->getConf('show login')) {
            $controller->register_hook('TPL_CONTENT_DISPLAY', 'AFTER', $this, 'append_to_content');
        }
    }

    public function handle_html_loginform_output(Doku_Event &$event, $param) {
        global $auth;
        if (!($auth instanceof auth_plugin_sfauth)) {
            return;
        }

        $this->displayLogin();
    }

    private function displayLogin($linkToLoginForm = false) {
        global $ID;
        echo '<div class="sfauth">';

        printf('<a href="%s" class="sf">%s</a>',
            wl($ID, array('do' => 'login', 'u' => 'a')), hsc($this->getLang('login link')));
        if ($linkToLoginForm) {
            printf('<br/>');
            printf('<a href="?do=login">%s</a>', hsc($this->getLang('normal login')));
        }
        echo '</div>';
    }

    public function append_to_content(Doku_Event &$event, $param) {
        global $ACT;
        if ($ACT != 'denied' || $_SERVER['REMOTE_USER']) {
            return;
        }

        $this->displayLogin(true);
    }

    public function handle_login(Doku_Event &$event, $param) {
        global $ID;
        if (!isset($_GET['code'])) {
            return;
        }
        $id = $ID;
        if (isset($_SESSION['sfauth_redirect'])) {
            $id = $_SESSION['sfauth_redirect'];
            unset($_SESSION['sfauth_redirect']);
        }
        send_redirect(wl($id, '', true, '&'));
    }
}

// vim:ts=4:sw=4:et:
