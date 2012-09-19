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
    }

    public function handle_html_loginform_output(Doku_Event &$event, $param) {
        global $auth;
        if (!($auth instanceof auth_sfauth)) {
            return;
        }

        echo '<div class="sfauth">';
        printf('<a href="%s">%s</a>',
            hsc(DOKU_URL.'doku.php?do=login&u=a'), hsc($this->getLang('login link')));
        echo '</div>';
    }

}

// vim:ts=4:sw=4:et:
