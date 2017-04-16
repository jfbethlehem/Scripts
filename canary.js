/*
 Canary script.
 
 This script allows detection of successful cross site scripting (XSS) in a page
 done through overloading commong XSS-searching functions. This will only trigger
 when successful XSS is done. Alerting can be done by monitoring the configured
 file.
 */

var image  = '//jf.bethlehem.eu/canary/logger.php'; //or another non-existant page to trigger the WAF logging
var low_ie = (document.all && !document.querySelector);

function ci(src) {
    var img = low_ie ? new Image() : document.createElement('img');
    img.src = src;
    return img;
}

function create_image(src)
{
    var img = ci(src);
    img.style.width = '1px';
    img.style.height = '1px';
    document.body.appendChild(img);
}

var prox_alert = window.alert;
window.alert = function() {
    var joined = Array.prototype.slice.call(arguments).join('');
    create_image(image + '?type=alert&msg=' + joined + '&loc=' + encodeURI(window.location.href));
    
    if (low_ie)
        return prox_alert(joined)
        else
            return prox_alert.apply(this, arguments);
};

var prox_confirm = window.confirm;
window.confirm = function() {
    var joined = Array.prototype.slice.call(arguments).join('');
    create_image(image + '?type=confirm&msg=' + joined + '&loc=' + encodeURI(window.location.href));
    
    if (low_ie)
        return prox_confirm(joined)
        else
            return prox_confirm.apply(this, arguments);
};

var prox_prompt = window.prompt;
window.prompt = function() {
    var joined = Array.prototype.slice.call(arguments).join('');
    create_image(image + '?type=prompt&msg=' + joined + '&loc=' + encodeURI(window.location.href));
    
    if (low_ie)
        return prox_prompt(joined)
        else
            return prox_prompt.apply(this, arguments);
};
