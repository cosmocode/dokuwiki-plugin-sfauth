jQuery(function(){
    var $sfAuth = jQuery('.sfauth');
    var $dwAuth = jQuery('#dw__login');
    if(!$sfAuth.length) return;

    var link = document.createElement('a');
    link.className = 'switch';
    link.href = '#';
    link.innerHTML = LANG.plugins.sfauth.switch;

    link.onclick = function() {
        $dwAuth.dw_toggle();
    };

    $sfAuth.append(link);
    $dwAuth.hide();
});