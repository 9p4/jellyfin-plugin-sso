using System;
using System.Globalization;
using System.Text.Json;

namespace Jellyfin.Plugin.SSO_Auth;

/// <summary>
/// A helper class to return HTML for the client's auth flow.
/// </summary>
public static class WebResponse
{
    /// <summary>
    /// The shared HTML between all of the responses.
    /// </summary>
    public static readonly string Base = @"<!DOCTYPE html>
<html><head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
</head><body>
<p>Logging in...</p>
<noscript>Please enable Javascript to complete the login</noscript>
<script type='module'>
import QRCodeStyling from '/ssoviews/qr-code-styling.esm.js';
window.QRCodeStyling = QRCodeStyling;

function isTv() {
    // This is going to be really difficult to get right
    const userAgent = navigator.userAgent.toLowerCase();

    // The OculusBrowsers userAgent also has the samsungbrowser defined but is not a tv.
    if (userAgent.indexOf('oculusbrowser') !== -1) {
        return false;
    }

    if (userAgent.indexOf('tv') !== -1) {
        return true;
    }

    if (userAgent.indexOf('samsungbrowser') !== -1) {
        return true;
    }

    if (userAgent.indexOf('viera') !== -1) {
        return true;
    }

    return isWeb0s();
}

function isWeb0s() {
    const userAgent = navigator.userAgent.toLowerCase();

    return userAgent.indexOf('netcast') !== -1
        || userAgent.indexOf('web0s') !== -1;
}

function isMobile(userAgent) {
    const terms = [
        'mobi',
        'ipad',
        'iphone',
        'ipod',
        'silk',
        'gt-p1000',
        'nexus 7',
        'kindle fire',
        'opera mini'
    ];

    const lower = userAgent.toLowerCase();

    for (let i = 0, length = terms.length; i < length; i++) {
        if (lower.indexOf(terms[i]) !== -1) {
            return true;
        }
    }

    return false;
}

function hasKeyboard(browser) {
    if (browser.touch) {
        return true;
    }

    if (browser.xboxOne) {
        return true;
    }

    if (browser.ps4) {
        return true;
    }

    if (browser.edgeUwp) {
        // This is OK for now, but this won't always be true
        // Should we use this?
        // https://gist.github.com/wagonli/40d8a31bd0d6f0dd7a5d
        return true;
    }

    return !!browser.tv;
}

function iOSversion() {
    // MacIntel: Apple iPad Pro 11 iOS 13.1
    if (/iP(hone|od|ad)|MacIntel/.test(navigator.platform)) {
        const tests = [
            // Original test for getting full iOS version number in iOS 2.0+
            /OS (\d+)_(\d+)_?(\d+)?/,
            // Test for iPads running iOS 13+ that can only get the major OS version
            /Version\/(\d+)/
        ];
        for (const test of tests) {
            const matches = (navigator.appVersion).match(test);
            if (matches) {
                return [
                    parseInt(matches[1], 10),
                    parseInt(matches[2] || 0, 10),
                    parseInt(matches[3] || 0, 10)
                ];
            }
        }
    }
    return [];
}

function web0sVersion(browser) {
    // Detect webOS version by web engine version

    if (browser.chrome) {
        const userAgent = navigator.userAgent.toLowerCase();

        if (userAgent.indexOf('netcast') !== -1) {
            // The built-in browser (NetCast) may have a version that doesn't correspond to the actual web engine
            // Since there is no reliable way to detect webOS version, we return an undefined version

            console.warn('Unable to detect webOS version - NetCast');

            return undefined;
        }

        // The next is only valid for the app

        if (browser.versionMajor >= 94) {
            return 23;
        } else if (browser.versionMajor >= 87) {
            return 22;
        } else if (browser.versionMajor >= 79) {
            return 6;
        } else if (browser.versionMajor >= 68) {
            return 5;
        } else if (browser.versionMajor >= 53) {
            return 4;
        } else if (browser.versionMajor >= 38) {
            return 3;
        } else if (browser.versionMajor >= 34) {
            // webOS 2 browser
            return 2;
        } else if (browser.versionMajor >= 26) {
            // webOS 1 browser
            return 1;
        }
    } else if (browser.versionMajor >= 538) {
        // webOS 2 app
        return 2;
    } else if (browser.versionMajor >= 537) {
        // webOS 1 app
        return 1;
    }

    console.error('Unable to detect webOS version');

    return undefined;
}

let _supportsCssAnimation;
let _supportsCssAnimationWithPrefix;
function supportsCssAnimation(allowPrefix) {
    // TODO: Assess if this is still needed, as all of our targets should natively support CSS animations.
    if (allowPrefix && (_supportsCssAnimationWithPrefix === true || _supportsCssAnimationWithPrefix === false)) {
        return _supportsCssAnimationWithPrefix;
    }
    if (_supportsCssAnimation === true || _supportsCssAnimation === false) {
        return _supportsCssAnimation;
    }

    let animation = false;
    const domPrefixes = ['Webkit', 'O', 'Moz'];
    const elm = document.createElement('div');

    if (elm.style.animationName !== undefined) {
        animation = true;
    }

    if (animation === false && allowPrefix) {
        for (const domPrefix of domPrefixes) {
            if (elm.style[domPrefix + 'AnimationName'] !== undefined) {
                animation = true;
                break;
            }
        }
    }

    if (allowPrefix) {
        _supportsCssAnimationWithPrefix = animation;
        return _supportsCssAnimationWithPrefix;
    } else {
        _supportsCssAnimation = animation;
        return _supportsCssAnimation;
    }
}

const uaMatch = function (ua) {
    ua = ua.toLowerCase();

    const match = /(chrome)[ /]([\w.]+)/.exec(ua)
        || /(edg)[ /]([\w.]+)/.exec(ua)
        || /(edga)[ /]([\w.]+)/.exec(ua)
        || /(edgios)[ /]([\w.]+)/.exec(ua)
        || /(edge)[ /]([\w.]+)/.exec(ua)
        || /(opera)[ /]([\w.]+)/.exec(ua)
        || /(opr)[ /]([\w.]+)/.exec(ua)
        || /(safari)[ /]([\w.]+)/.exec(ua)
        || /(firefox)[ /]([\w.]+)/.exec(ua)
        || ua.indexOf('compatible') < 0 && /(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua)
        || [];

    const versionMatch = /(version)[ /]([\w.]+)/.exec(ua);

    let platform_match = /(ipad)/.exec(ua)
        || /(iphone)/.exec(ua)
        || /(windows)/.exec(ua)
        || /(android)/.exec(ua)
        || [];

    let browser = match[1] || '';

    if (browser === 'edge') {
        platform_match = [''];
    }

    if (browser === 'opr') {
        browser = 'opera';
    }

    let version;
    if (versionMatch && versionMatch.length > 2) {
        version = versionMatch[2];
    }

    version = version || match[2] || '0';

    let versionMajor = parseInt(version.split('.')[0], 10);

    if (isNaN(versionMajor)) {
        versionMajor = 0;
    }

    return {
        browser: browser,
        version: version,
        platform: platform_match[0] || '',
        versionMajor: versionMajor
    };
};

const userAgent = navigator.userAgent;

const matched = uaMatch(userAgent);
const browser = {};

if (matched.browser) {
    browser[matched.browser] = true;
    browser.version = matched.version;
    browser.versionMajor = matched.versionMajor;
}

if (matched.platform) {
    browser[matched.platform] = true;
}

browser.edgeChromium = browser.edg || browser.edga || browser.edgios;

if (!browser.chrome && !browser.edgeChromium && !browser.edge && !browser.opera && userAgent.toLowerCase().indexOf('webkit') !== -1) {
    browser.safari = true;
}

browser.osx = userAgent.toLowerCase().indexOf('mac os x') !== -1;

// This is a workaround to detect iPads on iOS 13+ that report as desktop Safari
// This may break in the future if Apple releases a touchscreen Mac
// https://forums.developer.apple.com/thread/119186
if (browser.osx && !browser.iphone && !browser.ipod && !browser.ipad && navigator.maxTouchPoints > 1) {
    browser.ipad = true;
}

if (userAgent.toLowerCase().indexOf('playstation 4') !== -1) {
    browser.ps4 = true;
    browser.tv = true;
}

if (isMobile(userAgent)) {
    browser.mobile = true;
}

if (userAgent.toLowerCase().indexOf('xbox') !== -1) {
    browser.xboxOne = true;
    browser.tv = true;
}
browser.animate = typeof document !== 'undefined' && document.documentElement.animate != null;
browser.hisense = userAgent.toLowerCase().includes('hisense');
browser.tizen = userAgent.toLowerCase().indexOf('tizen') !== -1 || window.tizen != null;
browser.vidaa = userAgent.toLowerCase().includes('vidaa');
browser.web0s = isWeb0s();
browser.edgeUwp = browser.edge && (userAgent.toLowerCase().indexOf('msapphost') !== -1 || userAgent.toLowerCase().indexOf('webview') !== -1);

if (browser.web0s) {
    browser.web0sVersion = web0sVersion(browser);
} else if (browser.tizen) {
    // UserAgent string contains 'Safari' and 'safari' is set by matched browser, but we only want 'tizen' to be true
    delete browser.safari;

    const v = (navigator.appVersion).match(/Tizen (\d+).(\d+)/);
    browser.tizenVersion = parseInt(v[1], 10);
} else {
    browser.orsay = userAgent.toLowerCase().indexOf('smarthub') !== -1;
}

if (browser.edgeUwp) {
    browser.edge = true;
}

browser.tv = isTv();
browser.operaTv = browser.tv && userAgent.toLowerCase().indexOf('opr/') !== -1;

if (browser.mobile || browser.tv) {
    browser.slow = true;
}

/* eslint-disable-next-line compat/compat */
if (typeof document !== 'undefined' && ('ontouchstart' in window) || (navigator.maxTouchPoints > 0)) {
    browser.touch = true;
}

browser.keyboard = hasKeyboard(browser);
browser.supportsCssAnimation = supportsCssAnimation;

browser.iOS = browser.ipad || browser.iphone || browser.ipod;

if (browser.iOS) {
    browser.iOSVersion = iOSversion();

    if (browser.iOSVersion && browser.iOSVersion.length >= 2) {
        browser.iOSVersion = browser.iOSVersion[0] + (browser.iOSVersion[1] / 10);
    }
}

function getDeviceName() {
	var deviceName = '';
    if (!deviceName) {
        if (browser.tizen) {
            deviceName = 'Samsung Smart TV';
        } else if (browser.web0s) {
            deviceName = 'LG Smart TV';
        } else if (browser.operaTv) {
            deviceName = 'Opera TV';
        } else if (browser.xboxOne) {
            deviceName = 'Xbox One';
        } else if (browser.ps4) {
            deviceName = 'Sony PS4';
        } else if (browser.chrome) {
            deviceName = 'Chrome';
        } else if (browser.edgeChromium) {
            deviceName = 'Edge Chromium';
        } else if (browser.edge) {
            deviceName = 'Edge';
        } else if (browser.firefox) {
            deviceName = 'Firefox';
        } else if (browser.opera) {
            deviceName = 'Opera';
        } else if (browser.safari) {
            deviceName = 'Safari';
        } else {
            deviceName = 'Web Browser';
        }

        if (browser.ipad) {
            deviceName += ' iPad';
        } else if (browser.iphone) {
            deviceName += ' iPhone';
        } else if (browser.android) {
            deviceName += ' Android';
        }
    }

    return deviceName;
}

const sleep = (milliseconds) => {
    return new Promise(resolve => setTimeout(resolve, milliseconds))
}

";

    /// <summary>
    /// A generator for the web response that incorporates the data from the server.
    /// </summary>
    /// <param name="data">The data of the auth flow. Is signed XML for SAML and a state ID for OpenID.</param>
    /// <param name="provider">The name of the provider to callback to.</param>
    /// <param name="baseUrl">The base URL of the Jellyfin installation.</param>
    /// <param name="mode">The mode of the function; SAML or OID.</param>
    /// <param name="isLinking">Whether or not this request is to link accounts (Rather than authenticate).</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string Generator(string data, string provider, string baseUrl, string mode, bool isLinking = false)
    {
        // Strip out the protocol (http:// or https://) and convert the domain to Punycode
        var idnMapping = new IdnMapping();
        var protocolSeparatorIndex = baseUrl.IndexOf("//");
        var protocol = baseUrl.Substring(0, protocolSeparatorIndex + 2);
        var domain = baseUrl.Substring(protocolSeparatorIndex + 2);
        var punycodeDomain = idnMapping.GetAscii(domain);
        var punycodeBaseUrl = protocol + punycodeDomain;

        return Base + @"
async function link(request) {
    const jfCredentialsString = localStorage.getItem(""jellyfin_credentials"");

    if (jfCredentialsString == null) return;

    const jfCredentials = JSON.parse(jfCredentialsString);
    const jfUser = jfCredentials['Servers'][0]['UserId'];
    const jfToken = jfCredentials['Servers'][0]['AccessToken'];

    if (jfUser == null) return;
    if (jfToken == null) return;

    const url = '" + $"{punycodeBaseUrl}/sso/{mode}/Link/{provider}/" + @"' + jfUser;

    return new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');

       xhr.setRequestHeader(
           'X-Emby-Authorization', 
           `MediaBrowser Client=""${request.appName}"",Device=""${request.deviceName}"",DeviceId=""${request.deviceId}"",Version=""${request.appVersion}"",Token=""${jfToken}""`)

       xhr.onload = function(e) {
         resolve(xhr.response);
       };
       xhr.onerror = function (e) {
         console.log(e);
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
}

async function main() {
    localStorage.removeItem('jellyfin_credentials');
    document.getElementById('iframe-main').src = '" + punycodeBaseUrl + @"/web/index.html';

    var data = '" + data + @"';
    while (localStorage.getItem(""_deviceId2"") == null ||
        localStorage.getItem(""jellyfin_credentials"") == null ||
        JSON.parse(localStorage.getItem(""jellyfin_credentials""))['Servers'][0]['Id'] == null) {
        // If localStorage isn't initialized yet, try again.
        await sleep(100);
    }
    var deviceId = localStorage.getItem(""_deviceId2"");
    var appName = ""Jellyfin Web"";
    var appVersion = ""10.8.0"";
    var deviceName = getDeviceName();

    var request = {deviceId, appName, appVersion, deviceName, data};

    if (" + $"{isLinking}".ToLower() + @") await link(request);

    var url = '" + punycodeBaseUrl + "/sso/" + mode + "/Auth/" + provider + @"';

    let response = await new Promise(resolve => {
       var xhr = new XMLHttpRequest();
       xhr.open('POST', url, true);
       xhr.setRequestHeader('Content-Type', 'application/json');
       xhr.setRequestHeader('Accept', 'application/json');
       xhr.onload = function(e) {
         resolve(xhr.response);
       };
       xhr.onerror = function () {
         resolve(undefined);
       };
       xhr.send(JSON.stringify(request));
    })
    var responseJson = JSON.parse(response);
    var userId = 'user-' + responseJson['User']['Id'] + '-' + responseJson['User']['ServerId'];
    responseJson['User']['EnableAutoLogin'] = true;
    localStorage.setItem(userId, JSON.stringify(responseJson['User']));
    var jfCreds = JSON.parse(localStorage.getItem('jellyfin_credentials'));
    jfCreds['Servers'][0]['AccessToken'] = responseJson['AccessToken'];
    jfCreds['Servers'][0]['UserId'] = responseJson['User']['Id'];
    localStorage.setItem('jellyfin_credentials', JSON.stringify(jfCreds));
    localStorage.setItem('enableAutoLogin', 'true');
    window.location.replace('" + punycodeBaseUrl + @"/web/index.html');
}

document.addEventListener('DOMContentLoaded', function () {
    main();
});

// https://stackoverflow.com/a/25435165
</script>
<style>
  body {
    background: #101010;
    color: #d1cfce;
    font-family: Noto Sans, Noto Sans HK, Noto Sans JP, Noto Sans KR, Noto Sans SC, Noto Sans TC, sans-serif;
  }
</style>
<iframe id='iframe-main' class='docs-texteventtarget-iframe' sandbox='allow-same-origin allow-forms allow-scripts' src='' style='position: absolute;width:0;height:0;border:0;'></iframe></body></html>";
    }

    /// <summary>
    /// A generator for the device code flow web response with PKCE support.
    /// </summary>
    /// <param name="provider">The name of the provider.</param>
    /// <param name="baseUrl">The base URL of the Jellyfin installation.</param>
    /// <returns>A string with the HTML to serve to the client.</returns>
    public static string DeviceCodeGenerator(string provider, string baseUrl)
    {
        // Strip out the protocol and convert the domain to Punycode
        var idnMapping = new IdnMapping();
        var protocolSeparatorIndex = baseUrl.IndexOf("//");
        var protocol = baseUrl.Substring(0, protocolSeparatorIndex + 2);
        var domain = baseUrl.Substring(protocolSeparatorIndex + 2);
        var punycodeDomain = idnMapping.GetAscii(domain);
        var punycodeBaseUrl = protocol + punycodeDomain;

        return Base + @"
function dec2hex(dec) {
  return ('0' + dec.toString(16)).substr(-2);
}

function generateCodeVerifier() {
  var array = new Uint32Array(56 / 2);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec2hex).join('');
}

function sha256(plain) {
  // returns promise ArrayBuffer
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return window.crypto.subtle.digest('SHA-256', data);
}

function base64urlencode(a) {
  var str = '';
  var bytes = new Uint8Array(a);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function generateCodeChallenge(codeVerifier) {
    // code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    var hashed = await sha256(codeVerifier);
    var base64encoded = base64urlencode(hashed);
    return base64encoded;
}

async function loadJellyfinStyles(baseUrl) {
    try {
        // Link to Jellyfin's main stylesheet
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = baseUrl + '/web/themes/dark/theme.css';
        document.head.appendChild(link);

        // Fetch and apply custom CSS from branding configuration
        const response = await fetch(baseUrl + '/Branding/Configuration');
        const config = await response.json();

        if (config.CustomCss) {
            const style = document.createElement('style');
            style.textContent = config.CustomCss;
            document.head.appendChild(style);
        }
    } catch (error) {
        console.warn('Failed to load Jellyfin styles:', error);
    }
}

async function generateQRCode(text) {
    // Generate styled QR code using qr-code-styling (privacy-friendly, no external requests except library)
    const qrCode = new QRCodeStyling({
        width: 250,
        height: 250,
        type: 'canvas',
        data: text,
        qrOptions: {
            errorCorrectionLevel: 'M'
        },
        dotsOptions: {
            color: '#000000',
            type: 'rounded'
        },
        backgroundOptions: {
            color: '#FFFFFF'
        }
    });

    // Use getRawData to get the blob, then convert to data URL
    const blob = await qrCode.getRawData('png');
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result);
        reader.readAsDataURL(blob);
    });
}

async function initiateDeviceFlow(provider, baseUrl, codeChallenge) {
    const flowUrl = baseUrl + '/sso/OID/device/' + provider;

    return new Promise((resolve, reject) => {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', flowUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.setRequestHeader('Accept', 'application/json');

        xhr.onload = function(e) {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(JSON.parse(xhr.response));
            } else {
                reject(new Error('Device flow initiation failed: ' + xhr.statusText));
            }
        };

        xhr.onerror = function () {
            reject(new Error('Network error during device flow initiation'));
        };

        xhr.send(JSON.stringify({ codeChallenge }));
    });
}

async function pollDeviceCode(state, codeChallenge, provider, baseUrl, interval) {
    const pollUrl = baseUrl + '/sso/OID/devicePoll/' + provider + 
        '?state=' + encodeURIComponent(state) + 
        '&codeChallenge=' + encodeURIComponent(codeChallenge);

    while (true) {
        try {
            const response = await fetch(pollUrl);
            const data = await response.json();

            if (data.status === 'complete') {
                return { success: true };
            } else if (data.status === 'slow_down') {
                // Increase polling interval
                await sleep(interval * 2000);
            } else if (data.status === 'pending') {
                // Continue polling
                await sleep(interval * 1000);
            } else if (data.error) {
                return { success: false, error: data.error, error_description: data.error_description };
            } else {
                // Unknown status, keep trying
                await sleep(interval * 1000);
            }
        } catch (error) {
            console.error('Polling error:', error);
            await sleep(interval * 1000);
        }
    }
}

async function authenticateWithDeviceCode(provider, baseUrl, deviceInfo) {
    const authUrl = baseUrl + '/sso/OID/deviceAuth/' + provider;

    return new Promise((resolve, reject) => {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', authUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.setRequestHeader('Accept', 'application/json');

        xhr.onload = function(e) {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(JSON.parse(xhr.response));
            } else {
                reject(new Error('Authentication failed: ' + xhr.statusText));
            }
        };

        xhr.onerror = function () {
            reject(new Error('Network error during authentication'));
        };

        xhr.send(JSON.stringify(deviceInfo));
    });
}

async function main() {
    const provider = " + JsonSerializer.Serialize(provider) + @";
    const baseUrl = " + JsonSerializer.Serialize(punycodeBaseUrl) + @";

    // Load Jellyfin's styles and custom CSS
    await loadJellyfinStyles(baseUrl);

    // Update the UI to show initial loading state
    document.body.innerHTML = `
        <style>
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .device-auth-container {
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
                text-align: center;
            }
            .device-auth-box {
                background-color: var(--lighterGradientPoint, rgba(255, 255, 255, 0.05));
                border: var(--borderWidth, 1px) solid var(--borderColor, rgba(255, 255, 255, 0.1));
                border-radius: var(--largeRadius, 10px);
                padding: 30px;
                margin-bottom: 30px;
            }
            .device-auth-title {
                color: var(--textColor, #d1cfce);
                font-size: 2em;
                font-weight: 600;
                margin-bottom: 30px;
            }
            .device-auth-subtitle {
                color: var(--textColor, #d1cfce);
                font-size: 1.2em;
                font-weight: 600;
                margin-bottom: 20px;
            }
            .device-auth-code-box {
                background-color: var(--selectorBackgroundColor, rgba(255, 255, 255, 0.1));
                border-radius: var(--smallRadius, 5px);
                padding: 20px;
                display: inline-block;
                margin-top: 20px;
            }
            .device-auth-code {
                color: var(--textColor, #d1cfce);
                font-size: 2em;
                font-weight: bold;
                letter-spacing: 5px;
            }
            .device-auth-text {
                color: var(--dimTextColor, #9ca3af);
                margin-bottom: 15px;
                line-height: 1.6;
            }
        </style>

        <div class='device-auth-container'>
            <h1 class='device-auth-title'>Device Authentication</h1>

            <div class='device-auth-box'>
                <div id='status' style='display: flex; align-items: center; justify-content: center;'>
                    <div class='spinner' style='width: 20px; height: 20px; border: 3px solid rgba(255,255,255,0.2); border-top-color: currentColor; border-radius: 50%; animation: spin 1s linear infinite;'></div>
                    <span style='margin-left: 10px;'>Initializing authentication...</span>
                </div>
            </div>
        </div>
    `;

    try {
        // Generate PKCE code_verifier and code_challenge
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(codeVerifier);

        console.log('Generated PKCE credentials');
        console.log('Code verifier length:', codeVerifier.length);
        console.log('Code challenge length:', codeChallenge.length);

        // Initiate device authorization flow with code_challenge
        const deviceFlowData = await initiateDeviceFlow(provider, baseUrl, codeChallenge);

        const state = deviceFlowData.State;
        const userCode = deviceFlowData.UserCode;
        const verificationUri = deviceFlowData.VerificationUri;
        const verificationUriComplete = deviceFlowData.VerificationUriComplete || (verificationUri + '?user_code=' + encodeURIComponent(userCode));
        const interval = deviceFlowData.Interval || 5;

        // Update UI with verification instructions
        document.body.innerHTML = `
            <style>
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .device-auth-container {
                    max-width: 600px;
                    margin: 50px auto;
                    padding: 20px;
                    text-align: center;
                }
                .device-auth-box {
                    background-color: var(--lighterGradientPoint, rgba(255, 255, 255, 0.05));
                    border: var(--borderWidth, 1px) solid var(--borderColor, rgba(255, 255, 255, 0.1));
                    border-radius: var(--largeRadius, 10px);
                    padding: 30px;
                    margin-bottom: 30px;
                }
                .device-auth-title {
                    color: var(--textColor, #d1cfce);
                    font-size: 2em;
                    font-weight: 600;
                    margin-bottom: 30px;
                }
                .device-auth-subtitle {
                    color: var(--textColor, #d1cfce);
                    font-size: 1.2em;
                    font-weight: 600;
                    margin-bottom: 20px;
                }
                .device-auth-code-box {
                    background-color: var(--selectorBackgroundColor, rgba(255, 255, 255, 0.1));
                    border-radius: var(--smallRadius, 5px);
                    padding: 20px;
                    display: inline-block;
                    margin-top: 20px;
                }
                .device-auth-code {
                    color: var(--textColor, #d1cfce);
                    font-size: 2em;
                    font-weight: bold;
                    letter-spacing: 5px;
                }
                .device-auth-text {
                    color: var(--dimTextColor, #9ca3af);
                    margin-bottom: 15px;
                    line-height: 1.6;
                }
            </style>

            <div class='device-auth-container'>
                <h1 class='device-auth-title'>Device Authentication</h1>
                
                <div class='device-auth-box'>
                    <div id='status' style='display: flex; align-items: center; justify-content: center;'>
                        <div class='spinner' style='width: 20px; height: 20px; border: 3px solid rgba(255,255,255,0.2); border-top-color: currentColor; border-radius: 50%; animation: spin 1s linear infinite;'></div>
                        <span style='margin-left: 10px;'>Waiting for authentication...</span>
                    </div>
                </div>

                <div class='device-auth-box'>
                    <h2 class='device-auth-subtitle'>Scan this code to log in to Jellyfin:</h2>

                    <div style='margin-bottom: 30px;'>
                        <img id='qr-code-image' src='' alt='QR Code' style='width: 250px; height: 250px; border-radius: var(--smallRadius, 5px);'/>
                    </div>

                    <p class='device-auth-text'>
                        If you can't scan the QR code, go to <a href='${verificationUri}' target='_blank' class='button-link' style='text-decoration: underline;'>${verificationUri}</a> and enter the code:
                    </p>

                    <div class='device-auth-code-box'>
                        <span class='device-auth-code'>${userCode}</span>
                    </div>
                </div>
            </div>
        `;

        // Generate QR code asynchronously after DOM is ready
        const qrCodeDataUrl = await generateQRCode(verificationUriComplete);
        document.getElementById('qr-code-image').src = qrCodeDataUrl;

        // Wait for localStorage to be ready
        while (localStorage.getItem(""_deviceId2"") == null) {
            await sleep(100);
        }

        var deviceId = localStorage.getItem(""_deviceId2"");
        var appName = ""Jellyfin Web"";
        var appVersion = ""10.11.0"";
        var deviceName = getDeviceName();

        // Start polling for device authorization
        const pollResult = await pollDeviceCode(state, codeChallenge, provider, baseUrl, interval);

        if (!pollResult.success) {
            document.getElementById('status').innerHTML = `
                <span style='color: #ff4444;'>❌ Authentication failed: ${pollResult.error_description || pollResult.error}</span>
            `;
            return;
        }

        // Device code is now authorized, proceed with authentication
        document.getElementById('status').innerHTML = `
            <div class='spinner' style='display: inline-block; width: 20px; height: 20px; border: 3px solid rgba(255,255,255,0.2); border-top-color: currentColor; border-radius: 50%; animation: spin 1s linear infinite;'></div>
            <span style='margin-left: 10px;'>Authentication successful! Completing login...</span>
        `;

        // Wait for iframe to initialize jellyfin credentials structure
        localStorage.removeItem('jellyfin_credentials');
        const iframe = document.createElement('iframe');
        iframe.id = 'iframe-main';
        iframe.className = 'docs-texteventtarget-iframe';
        iframe.sandbox = 'allow-same-origin allow-forms allow-scripts';
        iframe.src = baseUrl + '/web/index.html';
        iframe.style.cssText = 'position: absolute;width:0;height:0;border:0;';
        document.body.appendChild(iframe);

        while (localStorage.getItem(""jellyfin_credentials"") == null ||
            JSON.parse(localStorage.getItem(""jellyfin_credentials""))['Servers'][0]['Id'] == null) {
            await sleep(100);
        }

        // Authenticate with the state and code_verifier
        var deviceInfo = {
            deviceId,
            appName,
            appVersion,
            deviceName,
            data: state,
            codeVerifier: codeVerifier
        };

        const authResult = await authenticateWithDeviceCode(provider, baseUrl, deviceInfo);

        // Store authentication result
        var userId = 'user-' + authResult['User']['Id'] + '-' + authResult['User']['ServerId'];
        authResult['User']['EnableAutoLogin'] = true;
        localStorage.setItem(userId, JSON.stringify(authResult['User']));

        var jfCreds = JSON.parse(localStorage.getItem('jellyfin_credentials'));
        jfCreds['Servers'][0]['AccessToken'] = authResult['AccessToken'];
        jfCreds['Servers'][0]['UserId'] = authResult['User']['Id'];
        localStorage.setItem('jellyfin_credentials', JSON.stringify(jfCreds));
        localStorage.setItem('enableAutoLogin', 'true');

        // Redirect to Jellyfin
        window.location.replace(baseUrl + '/web/index.html');
    } catch (error) {
        console.error('Error during device code flow:', error);
        document.getElementById('status').innerHTML = `
            <span style='color: #ff4444;'>❌ Error: ${error.message}</span>
        `;
    }
}

document.addEventListener('DOMContentLoaded', function () {
    main();
});

</script></body></html>";
    }
}
