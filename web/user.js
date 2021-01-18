//
/******************************************************************************
 * user.js                                                                    *
 * https://github.com/pyllyukko/user.js                                       *
 ******************************************************************************/

/******************************************************************************
 * SECTION: HTML5 / APIs / DOM                                                *
 ******************************************************************************/

// PREF: Disable Service Workers
// https://developer.mozilla.org/en-US/docs/Web/API/Worker
// https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker_API
// https://wiki.mozilla.org/Firefox/Push_Notifications#Service_Workers
// NOTICE: Disabling ServiceWorkers breaks functionality on some sites (Google Street View...)
// Unknown security implications
// CVE-2016-5259, CVE-2016-2812, CVE-2016-1949, CVE-2016-5287 (fixed)
user_pref("dom.serviceWorkers.enabled",				false);

// PREF: Disable web notifications
// https://support.mozilla.org/en-US/questions/1140439
user_pref("dom.webnotifications.enabled",			true);

// PREF: Disable DOM timing API
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
// https://www.w3.org/TR/navigation-timing/#privacy
user_pref("dom.enable_performance",				false);

// PREF: Make sure the User Timing API does not provide a new high resolution timestamp
// https://trac.torproject.org/projects/tor/ticket/16336
// https://www.w3.org/TR/2013/REC-user-timing-20131212/#privacy-security
user_pref("dom.enable_user_timing",				false);

// PREF: Disable Web Audio API
// https://bugzilla.mozilla.org/show_bug.cgi?id=1288359
// NOTICE: Web Audio API is required for Unity web player/games
user_pref("dom.webaudio.enabled",				false);

// PREF: Disable Location-Aware Browsing (geolocation)
// https://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",					false);

// PREF: When geolocation is enabled, use Mozilla geolocation service instead of Google
// https://bugzilla.mozilla.org/show_bug.cgi?id=689252
user_pref("geo.wifi.uri", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");

// PREF: When geolocation is enabled, don't log geolocation requests to the console
user_pref("geo.wifi.logging.enabled", false);

// PREF: Disable raw TCP socket support (mozTCPSocket)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
user_pref("dom.mozTCPSocket.enabled",				false);

// PREF: Disable DOM storage (disabled)
// http://kb.mozillazine.org/Dom.storage.enabled
// https://html.spec.whatwg.org/multipage/webstorage.html
// NOTICE-DISABLED: Disabling DOM storage is known to cause`TypeError: localStorage is null` errors
//user_pref("dom.storage.enabled",		false);

// PREF: Disable leaking network/browser connection information via Javascript
// Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
user_pref("dom.netinfo.enabled",				false);

// PREF: Disable network API (Firefox < 32)
// https://developer.mozilla.org/en-US/docs/Web/API/Connection/onchange
// https://www.torproject.org/projects/torbrowser/design/#fingerprinting-defenses
user_pref("dom.network.enabled",				false);

// PREF: Disable WebRTC entirely to prevent leaking internal IP addresses (Firefox < 42)
// NOTICE: Disabling WebRTC breaks peer-to-peer file sharing tools (reep.io ...)
user_pref("media.peerconnection.enabled",			false);

// PREF: Don't reveal your internal IP when WebRTC is enabled (Firefox >= 42)
// https://wiki.mozilla.org/Media/WebRTC/Privacy
// https://github.com/beefproject/beef/wiki/Module%3A-Get-Internal-IP-WebRTC
user_pref("media.peerconnection.ice.default_address_only",	true); // Firefox 42-51
user_pref("media.peerconnection.ice.no_host",			true); // Firefox >= 52

// PREF: Disable WebRTC getUserMedia, screen sharing, audio capture, video capture
// https://wiki.mozilla.org/Media/getUserMedia
// https://blog.mozilla.org/futurereleases/2013/01/12/capture-local-camera-and-microphone-streams-with-getusermedia-now-enabled-in-firefox/
// https://developer.mozilla.org/en-US/docs/Web/API/Navigator
user_pref("media.navigator.enabled",				false);
user_pref("media.navigator.video.enabled",			false);
user_pref("media.getusermedia.screensharing.enabled",		false);
user_pref("media.getusermedia.audiocapture.enabled",		false);

// PREF: Disable battery API (Firefox < 52)
// https://developer.mozilla.org/en-US/docs/Web/API/BatteryManager
// https://bugzilla.mozilla.org/show_bug.cgi?id=1313580
user_pref("dom.battery.enabled",				false);

// PREF: Disable telephony API
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
user_pref("dom.telephony.enabled",				false);

// PREF: Disable "beacon" asynchronous HTTP transfers (used for analytics)
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled",					false);

// PREF: Disable clipboard event detection (onCut/onCopy/onPaste) via Javascript
// NOTICE: Disabling clipboard events breaks Ctrl+C/X/V copy/cut/paste functionaility in JS-based web applications (Google Docs...)
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/dom.event.clipboardevents.enabled
user_pref("dom.event.clipboardevents.enabled",			false);

// PREF: Disable "copy to clipboard" functionality via Javascript (Firefox >= 41)
// NOTICE: Disabling clipboard operations will break legitimate JS-based "copy to clipboard" functionality
// https://hg.mozilla.org/mozilla-central/rev/2f9f8ea4b9c3
user_pref("dom.allow_cut_copy", true);

// PREF: Disable speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechRecognition
// https://wiki.mozilla.org/HTML5_Speech_API
user_pref("media.webspeech.recognition.enable",			false);

// PREF: Disable speech synthesis
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis
user_pref("media.webspeech.synth.enabled",			false);

// PREF: Disable sensor API
// https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",				false);

// PREF: Disable pinging URIs specified in HTML <a> ping= attributes
// http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings",					false);

// PREF: When browser pings are enabled, only allow pinging the same host as the origin page
// http://kb.mozillazine.org/Browser.send_pings.require_same_host
user_pref("browser.send_pings.require_same_host",		true);

// PREF: Disable IndexedDB (disabled)
// https://developer.mozilla.org/en-US/docs/IndexedDB
// https://en.wikipedia.org/wiki/Indexed_Database_API
// https://wiki.mozilla.org/Security/Reviews/Firefox4/IndexedDB_Security_Review
// http://forums.mozillazine.org/viewtopic.php?p=13842047
// https://github.com/pyllyukko/user.js/issues/8
// NOTICE-DISABLED: IndexedDB could be used for tracking purposes, but is required for some add-ons to work (notably uBlock), so is left enabled
//user_pref("dom.indexedDB.enabled",		false);

// TODO: "Access Your Location" "Maintain Offline Storage" "Show Notifications"

// PREF: Disable gamepad API to prevent USB device enumeration
// https://www.w3.org/TR/gamepad/
// https://trac.torproject.org/projects/tor/ticket/13023
user_pref("dom.gamepad.enabled",				false);

// PREF: Disable virtual reality devices APIs
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
// https://developer.mozilla.org/en-US/docs/Web/API/WebVR_API
user_pref("dom.vr.enabled",					false);

// PREF: Disable vibrator API
user_pref("dom.vibrator.enabled",           false);

// PREF: Disable resource timing API
// https://www.w3.org/TR/resource-timing/#privacy-security
user_pref("dom.enable_resource_timing",				false);

// PREF: Disable Archive API (Firefox < 54)
// https://wiki.mozilla.org/WebAPI/ArchiveAPI
// https://bugzilla.mozilla.org/show_bug.cgi?id=1342361
user_pref("dom.archivereader.enabled",				false);

// PREF: Disable webGL
// https://en.wikipedia.org/wiki/WebGL
// https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
user_pref("webgl.disabled",					true);
// PREF: When webGL is enabled, use the minimum capability mode
user_pref("webgl.min_capability_mode",				true);
// PREF: When webGL is enabled, disable webGL extensions
// https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API#WebGL_debugging_and_testing
user_pref("webgl.disable-extensions",				true);
// PREF: When webGL is enabled, force enabling it even when layer acceleration is not supported
// https://trac.torproject.org/projects/tor/ticket/18603
user_pref("webgl.disable-fail-if-major-performance-caveat",	true);
// PREF: When webGL is enabled, do not expose information about the graphics driver
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
user_pref("webgl.enable-debug-renderer-info",			false);
// somewhat related...
//user_pref("pdfjs.enableWebGL",					false);

// PREF: Spoof dual-core CPU
// https://trac.torproject.org/projects/tor/ticket/21675
// https://bugzilla.mozilla.org/show_bug.cgi?id=1360039
user_pref("dom.maxHardwareConcurrency",				2);

// PREF: Disable WebAssembly
// https://webassembly.org/
// https://en.wikipedia.org/wiki/WebAssembly
// https://trac.torproject.org/projects/tor/ticket/21549
// NOTICE: WebAssembly is required for Unity web player/games
user_pref("javascript.options.wasm",				false);

/******************************************************************************
 * SECTION: Misc                                                              *
 ******************************************************************************/

// PREF: Disable face detection
user_pref("camera.control.face_detection.enabled",		false);

// PREF: Disable GeoIP lookup on your address to set default search engine region
// https://trac.torproject.org/projects/tor/ticket/16254
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
user_pref("browser.search.countryCode",				"US");
user_pref("browser.search.region",				"US");
user_pref("browser.search.geoip.url",				"");

// PREF: Set Accept-Language HTTP header to en-US regardless of Firefox localization
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
user_pref("intl.accept_languages",				"en-US, en");

// PREF: Don't use OS values to determine locale, force using Firefox locale setting
// http://kb.mozillazine.org/Intl.locale.matchOS
user_pref("intl.locale.matchOS",				false);

// PREF: Don't use Mozilla-provided location-specific search engines
user_pref("browser.search.geoSpecificDefaults",			false);

// PREF: Do not automatically send selection to clipboard on some Linux platforms
// http://kb.mozillazine.org/Clipboard.autocopy
user_pref("clipboard.autocopy",					false);

// PREF: Prevent leaking application locale/date format using JavaScript
// https://bugzilla.mozilla.org/show_bug.cgi?id=867501
// https://hg.mozilla.org/mozilla-central/rev/52d635f2b33d
user_pref("javascript.use_us_english_locale",			true);

// PREF: Do not submit invalid URIs entered in the address bar to the default search engine
// http://kb.mozillazine.org/Keyword.enabled
user_pref("keyword.enabled",					true);

// PREF: Don't trim HTTP off of URLs in the address bar.
// https://bugzilla.mozilla.org/show_bug.cgi?id=665580
user_pref("browser.urlbar.trimURLs",				false);

// PREF: Don't try to guess domain names when entering an invalid domain name in URL bar
// http://www-archive.mozilla.org/docs/end-user/domain-guessing.html
user_pref("browser.fixup.alternate.enabled",			false);

// PREF: When browser.fixup.alternate.enabled is enabled, strip password from 'user:password@...' URLs
// https://github.com/pyllyukko/user.js/issues/290#issuecomment-303560851
user_pref("browser.fixup.hide_user_pass", true);

// PREF: Send DNS request through SOCKS when SOCKS proxying is in use
// https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/WebBrowsers
user_pref("network.proxy.socks_remote_dns",			true);

// PREF: Don't monitor OS online/offline connection state
// https://trac.torproject.org/projects/tor/ticket/18945
user_pref("network.manage-offline-status",			false);

// PREF: Enforce Mixed Active Content Blocking
// https://support.mozilla.org/t5/Protect-your-privacy/Mixed-content-blocking-in-Firefox/ta-p/10990
// https://developer.mozilla.org/en-US/docs/Site_Compatibility_for_Firefox_23#Non-SSL_contents_on_SSL_pages_are_blocked_by_default
// https://blog.mozilla.org/tanvi/2013/04/10/mixed-content-blocking-enabled-in-firefox-23/
user_pref("security.mixed_content.block_active_content",	true);

// PREF: Enforce Mixed Passive Content blocking (a.k.a. Mixed Display Content)
// NOTICE: Enabling Mixed Display Content blocking can prevent images/styles... from loading properly when connection to the website is only partially secured
user_pref("security.mixed_content.block_display_content",	true);

// PREF: Disable JAR from opening Unsafe File Types
// http://kb.mozillazine.org/Network.jar.open-unsafe-types
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.7 
user_pref("network.jar.open-unsafe-types",			false);

// CIS 2.7.4 Disable Scripting of Plugins by JavaScript
// http://forums.mozillazine.org/viewtopic.php?f=7&t=153889
user_pref("security.xpconnect.plugin.unrestricted",		false);

// PREF: Set File URI Origin Policy
// http://kb.mozillazine.org/Security.fileuri.strict_origin_policy
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.8
user_pref("security.fileuri.strict_origin_policy",		true);

// PREF: Disable Displaying Javascript in History URLs
// http://kb.mozillazine.org/Browser.urlbar.filter.javascript
// CIS 2.3.6 
user_pref("browser.urlbar.filter.javascript",			true);

// PREF: Disable asm.js
// http://asmjs.org/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
user_pref("javascript.options.asmjs",				false);

// PREF: Disable SVG in OpenType fonts
// https://wiki.mozilla.org/SVGOpenTypeFonts
// https://github.com/iSECPartners/publications/tree/master/reports/Tor%20Browser%20Bundle
user_pref("gfx.font_rendering.opentype_svg.enabled",		false);

// PREF: Disable in-content SVG rendering (Firefox >= 53) (disabled)
// NOTICE-DISABLED: Disabling SVG support breaks many UI elements on many sites
// https://bugzilla.mozilla.org/show_bug.cgi?id=1216893
// https://github.com/iSECPartners/publications/raw/master/reports/Tor%20Browser%20Bundle/Tor%20Browser%20Bundle%20-%20iSEC%20Deliverable%201.3.pdf#16
//user_pref("svg.disabled", true);


// PREF: Disable video stats to reduce fingerprinting threat
// https://bugzilla.mozilla.org/show_bug.cgi?id=654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
user_pref("media.video_stats.enabled",				false);

// PREF: Don't reveal build ID
// Value taken from Tor Browser
// https://bugzilla.mozilla.org/show_bug.cgi?id=583181
user_pref("general.buildID.override",				"20100101");
user_pref("browser.startup.homepage_override.buildID",		"20100101");

// PREF: Don't use document specified fonts to prevent installed font enumeration (fingerprinting)
// https://github.com/pyllyukko/user.js/issues/395
// https://browserleaks.com/fonts
// https://github.com/pyllyukko/user.js/issues/120
user_pref("browser.display.use_document_fonts",			1);

// PREF: Enable only whitelisted URL protocol handlers
// http://kb.mozillazine.org/Network.protocol-handler.external-default
// http://kb.mozillazine.org/Network.protocol-handler.warn-external-default
// http://kb.mozillazine.org/Network.protocol-handler.expose.%28protocol%29
// https://news.ycombinator.com/item?id=13047883
// https://bugzilla.mozilla.org/show_bug.cgi?id=167475
// https://github.com/pyllyukko/user.js/pull/285#issuecomment-298124005
// NOTICE: Disabling nonessential protocols breaks all interaction with custom protocols such as mailto:, irc:, magnet: ... and breaks opening third-party mail/messaging/torrent/... clients when clicking on links with these protocols
// TODO: Add externally-handled protocols from Windows 8.1 and Windows 10 (currently contains protocols only from Linux and Windows 7) that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
// TODO: Add externally-handled protocols from Mac OS X that might pose a similar threat (see e.g. https://news.ycombinator.com/item?id=13044991)
// If you want to enable a protocol, set network.protocol-handler.expose.(protocol) to true and network.protocol-handler.external.(protocol) to:
//   * true, if the protocol should be handled by an external application
//   * false, if the protocol should be handled internally by Firefox
user_pref("network.protocol-handler.warn-external-default",	true);
user_pref("network.protocol-handler.external.http",		false);
user_pref("network.protocol-handler.external.https",		false);
user_pref("network.protocol-handler.external.javascript",	false);
user_pref("network.protocol-handler.external.moz-extension",	false);
user_pref("network.protocol-handler.external.ftp",		false);
user_pref("network.protocol-handler.external.file",		false);
user_pref("network.protocol-handler.external.about",		false);
user_pref("network.protocol-handler.external.chrome",		false);
user_pref("network.protocol-handler.external.blob",		false);
user_pref("network.protocol-handler.external.data",		false);
user_pref("network.protocol-handler.expose-all",		false);
user_pref("network.protocol-handler.expose.http",		true);
user_pref("network.protocol-handler.expose.https",		true);
user_pref("network.protocol-handler.expose.javascript",		true);
user_pref("network.protocol-handler.expose.moz-extension",	true);
user_pref("network.protocol-handler.expose.ftp",		true);
user_pref("network.protocol-handler.expose.file",		true);
user_pref("network.protocol-handler.expose.about",		true);
user_pref("network.protocol-handler.expose.chrome",		true);
user_pref("network.protocol-handler.expose.blob",		true);
user_pref("network.protocol-handler.expose.data",		true);

/******************************************************************************
 * SECTION: Extensions / plugins                                                       *
 ******************************************************************************/

// PREF: Ensure you have a security delay when installing add-ons (milliseconds)
// http://kb.mozillazine.org/Disable_extension_install_delay_-_Firefox
// http://www.squarefree.com/2004/07/01/race-conditions-in-security-dialogs/
user_pref("security.dialog_enable_delay",			1000);

// PREF: Require signatures
// https://wiki.mozilla.org/Addons/Extension_Signing
//user_pref("xpinstall.signatures.required",		true);

// PREF: Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled",			false);

// PREF: Opt-out of themes (Persona) updates
// https://support.mozilla.org/t5/Firefox/how-do-I-prevent-autoamtic-updates-in-a-50-user-environment/td-p/144287
user_pref("lightweightThemes.update.enabled",			false);

// PREF: Disable Flash Player NPAPI plugin
// http://kb.mozillazine.org/Flash_plugin
user_pref("plugin.state.flash",					0);

// PREF: Disable Java NPAPI plugin
user_pref("plugin.state.java",					0);

// PREF: Disable sending Flash Player crash reports
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled",	false);

// PREF: When Flash crash reports are enabled, don't send the visited URL in the crash report
user_pref("dom.ipc.plugins.reportCrashURL",			false);

// PREF: When Flash is enabled, download and use Mozilla SWF URIs blocklist
// https://bugzilla.mozilla.org/show_bug.cgi?id=1237198
// https://github.com/mozilla-services/shavar-plugin-blocklist
user_pref("browser.safebrowsing.blockedURIs.enabled", true);

// PREF: Disable Gnome Shell Integration NPAPI plugin
user_pref("plugin.state.libgnome-shell-browser-plugin",		0);

// PREF: Disable the bundled OpenH264 video codec (disabled)
// http://forums.mozillazine.org/viewtopic.php?p=13845077&sid=28af2622e8bd8497b9113851676846b1#p13845077
//user_pref("media.gmp-provider.enabled",		false);

// PREF: Enable plugins click-to-play
// https://wiki.mozilla.org/Firefox/Click_To_Play
// https://blog.mozilla.org/security/2012/10/11/click-to-play-plugins-blocklist-style/
user_pref("plugins.click_to_play",				true);

// PREF: Updates addons automatically
// https://blog.mozilla.org/addons/how-to-turn-off-add-on-updates/
user_pref("extensions.update.enabled",				true);

// PREF: Enable add-on and certificate blocklists (OneCRL) from Mozilla
// https://wiki.mozilla.org/Blocklisting
// https://blocked.cdn.mozilla.net/
// http://kb.mozillazine.org/Extensions.blocklist.enabled
// http://kb.mozillazine.org/Extensions.blocklist.url
// https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/
// Updated at interval defined in extensions.blocklist.interval (default: 86400)
user_pref("extensions.blocklist.enabled",			true);
user_pref("services.blocklist.update_enabled",			true);

// PREF: Decrease system information leakage to Mozilla blocklist update servers
// https://trac.torproject.org/projects/tor/ticket/16931
user_pref("extensions.blocklist.url",				"https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");

// PREF: Disable system add-on updates (hidden & always-enabled add-ons from Mozilla)
// https://firefox-source-docs.mozilla.org/toolkit/mozapps/extensions/addon-manager/SystemAddons.html
// https://blog.mozilla.org/data/2018/08/20/effectively-measuring-search-in-firefox/
// https://github.com/pyllyukko/user.js/issues/419
// https://dxr.mozilla.org/mozilla-central/source/toolkit/mozapps/extensions/AddonManager.jsm#1248-1257
// NOTICE: Disabling system add-on updates prevents Mozilla from "hotfixing" your browser to patch critical problems (one possible use case from the documentation)
user_pref("extensions.systemAddon.update.enabled",		false);

/******************************************************************************
 * SECTION: Firefox (anti-)features / components                              *                            *
 ******************************************************************************/

// PREF: Disable Extension recommendations (Firefox >= 65)
// https://support.mozilla.org/en-US/kb/extension-recommendations
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr",	false);

// PREF: Trusted Recursive Resolver (DNS-over-HTTPS) (disabled)
// https://wiki.mozilla.org/Trusted_Recursive_Resolver
// 0=Off(default), 1=Reserved, 2=Try TRR first,3=Only use TRR,4=Reserved,5=Off by choice
user_pref("network.trr.mode",					5);

// PREF: Disable WebIDE
// https://trac.torproject.org/projects/tor/ticket/16222
// https://developer.mozilla.org/docs/Tools/WebIDE
user_pref("devtools.webide.enabled",				false);
user_pref("devtools.webide.autoinstallADBHelper",		false);
user_pref("devtools.webide.autoinstallFxdtAdapters",		false);

// PREF: Disable remote debugging
// https://developer.mozilla.org/en-US/docs/Tools/Remote_Debugging/Debugging_Firefox_Desktop
// https://developer.mozilla.org/en-US/docs/Tools/Tools_Toolbox#Advanced_settings
user_pref("devtools.debugger.remote-enabled",			false);
user_pref("devtools.chrome.enabled",				false);
user_pref("devtools.debugger.force-local",			true);

// PREF: Disable Mozilla telemetry/experiments
// https://wiki.mozilla.org/Platform/Features/Telemetry
// https://wiki.mozilla.org/Privacy/Reviews/Telemetry
// https://wiki.mozilla.org/Telemetry
// https://www.mozilla.org/en-US/legal/privacy/firefox.html#telemetry
// https://support.mozilla.org/t5/Firefox-crashes/Mozilla-Crash-Reporter/ta-p/1715
// https://wiki.mozilla.org/Security/Reviews/Firefox6/ReviewNotes/telemetry
// https://gecko.readthedocs.io/en/latest/browser/experiments/experiments/manifest.html
// https://wiki.mozilla.org/Telemetry/Experiments
// https://support.mozilla.org/en-US/questions/1197144
// https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/telemetry/internals/preferences.html#id1
user_pref("toolkit.telemetry.enabled",				false);
user_pref("toolkit.telemetry.unified",				false);
user_pref("toolkit.telemetry.archive.enabled",			false);
user_pref("experiments.supported",				false);
user_pref("experiments.enabled",				false);
user_pref("experiments.manifest.uri",				"");

// PREF: Disallow Necko to do A/B testing
// https://trac.torproject.org/projects/tor/ticket/13170
user_pref("network.allow-experiments",				false);

// PREF: Disable sending Firefox crash reports to Mozilla servers
// https://wiki.mozilla.org/Breakpad
// http://kb.mozillazine.org/Breakpad
// https://dxr.mozilla.org/mozilla-central/source/toolkit/crashreporter
// https://bugzilla.mozilla.org/show_bug.cgi?id=411490
// A list of submitted crash reports can be found at about:crashes
user_pref("breakpad.reportURL",					"");

// PREF: Disable sending reports of tab crashes to Mozilla (about:tabcrashed), don't nag user about unsent crash reports
// https://hg.mozilla.org/mozilla-central/file/tip/browser/app/profile/firefox.js
user_pref("browser.tabs.crashReporting.sendReport",		false);
user_pref("browser.crashReports.unsubmittedCheck.enabled",	false);

// PREF: Disable FlyWeb (discovery of LAN/proximity IoT devices that expose a Web interface)
// https://wiki.mozilla.org/FlyWeb
// https://wiki.mozilla.org/FlyWeb/Security_scenarios
// https://docs.google.com/document/d/1eqLb6cGjDL9XooSYEEo7mE-zKQ-o-AuDTcEyNhfBMBM/edit
// http://www.ghacks.net/2016/07/26/firefox-flyweb
user_pref("dom.flyweb.enabled",					false);

// PREF: Disable the UITour backend
// https://trac.torproject.org/projects/tor/ticket/19047#comment:3
user_pref("browser.uitour.enabled",				false);

// PREF: Enable Firefox Tracking Protection
// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
// https://kontaxis.github.io/trackingprotectionfirefox/
// https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/
user_pref("privacy.trackingprotection.enabled",			true);
user_pref("privacy.trackingprotection.pbmode.enabled",		true);

// PREF: Enable contextual identity Containers feature (Firefox >= 52)
// NOTICE: Containers are not available in Private Browsing mode
// https://wiki.mozilla.org/Security/Contextual_Identity_Project/Containers
user_pref("privacy.userContext.enabled",			true);

// PREF: Enable Firefox's anti-fingerprinting mode ("resist fingerprinting" or RFP) (Tor Uplift project)
// https://wiki.mozilla.org/Security/Tor_Uplift/Tracking
// https://bugzilla.mozilla.org/show_bug.cgi?id=1333933
// https://wiki.mozilla.org/Security/Fingerprinting
// NOTICE: RFP breaks some keyboard shortcuts used in certain websites (see #443)
// NOTICE: RFP changes your time zone
user_pref("privacy.resistFingerprinting",			true);

// PREF: disable mozAddonManager Web API [FF57+]
// https://bugzilla.mozilla.org/buglist.cgi?bug_id=1384330
// https://bugzilla.mozilla.org/buglist.cgi?bug_id=1406795
// https://bugzilla.mozilla.org/buglist.cgi?bug_id=1415644
// https://bugzilla.mozilla.org/buglist.cgi?bug_id=1453988
// https://trac.torproject.org/projects/tor/ticket/26114
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
user_pref("extensions.webextensions.restrictedDomains", "");

// PREF: enable RFP letterboxing / resizing of inner window [FF67+] (disabled)
// https://bugzilla.mozilla.org/1407366
//user_pref("privacy.resistFingerprinting.letterboxing", true);
//user_pref("privacy.resistFingerprinting.letterboxing.dimensions", "800x600, 1000x1000, 1600x900");

// PREF: disable showing about:blank/maximized window as soon as possible during startup [FF60+]
// https://bugzilla.mozilla.org/1448423
user_pref("browser.startup.blankWindow", false);

// PREF: Disable the built-in PDF viewer
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2743
// https://blog.mozilla.org/security/2015/08/06/firefox-exploit-found-in-the-wild/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-69/
user_pref("pdfjs.disabled",					true);

// PREF: Disable collection/sending of the health report (healthreport.sqlite*)
// https://support.mozilla.org/en-US/kb/firefox-health-report-understand-your-browser-perf
// https://gecko.readthedocs.org/en/latest/toolkit/components/telemetry/telemetry/preferences.html
user_pref("datareporting.healthreport.uploadEnabled",		false);
user_pref("datareporting.healthreport.service.enabled",		false);
user_pref("datareporting.policy.dataSubmissionEnabled",		false);
// "Allow Firefox to make personalized extension recommendations"
user_pref("browser.discovery.enabled",				false);

// PREF: Disable Shield/Heartbeat/Normandy (Mozilla user rating telemetry)
// https://wiki.mozilla.org/Advocacy/heartbeat
// https://trac.torproject.org/projects/tor/ticket/19047
// https://trac.torproject.org/projects/tor/ticket/18738
// https://wiki.mozilla.org/Firefox/Shield
// https://github.com/mozilla/normandy
// https://support.mozilla.org/en-US/kb/shield
// https://bugzilla.mozilla.org/show_bug.cgi?id=1370801
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("extensions.shield-recipe-client.enabled",		false);
user_pref("app.shield.optoutstudies.enabled",			false);


// PREF: Disable Firefox Hello (disabled) (Firefox < 49)
// https://wiki.mozilla.org/Loop
// https://support.mozilla.org/t5/Chat-and-share/Support-for-Hello-discontinued-in-Firefox-49/ta-p/37946
// NOTICE-DISABLED: Firefox Hello requires setting `media.peerconnection.enabled` and `media.getusermedia.screensharing.enabled` to true, `security.OCSP.require` to false to work.
//user_pref("loop.enabled",		false);

// PREF: Disable Firefox Hello metrics collection
// https://groups.google.com/d/topic/mozilla.dev.platform/nyVkCx-_sFw/discussion
user_pref("loop.logDomains",					false);

// PREF: Enable Auto Update (disabled)
// NOTICE: Fully automatic updates are disabled and left to package management systems on Linux. Windows users may want to change this setting.
// CIS 2.1.1
//user_pref("app.update.auto",					true);

// PREF: Enforce checking for Firefox updates
// http://kb.mozillazine.org/App.update.enabled
// NOTICE: Update check page might incorrectly report Firefox ESR as out-of-date
user_pref("app.update.enabled",                 true);

// PREF: Enable blocking reported web forgeries
// https://wiki.mozilla.org/Security/Safe_Browsing
// http://kb.mozillazine.org/Safe_browsing
// https://support.mozilla.org/en-US/kb/how-does-phishing-and-malware-protection-work
// http://forums.mozillazine.org/viewtopic.php?f=39&t=2711237&p=12896849#p12896849
// CIS 2.3.4
user_pref("browser.safebrowsing.enabled",			true); // Firefox < 50
user_pref("browser.safebrowsing.phishing.enabled",		true); // firefox >= 50

// PREF: Enable blocking reported attack sites
// http://kb.mozillazine.org/Browser.safebrowsing.malware.enabled
// CIS 2.3.5
user_pref("browser.safebrowsing.malware.enabled",		true);

// PREF: Disable querying Google Application Reputation database for downloaded binary files
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
user_pref("browser.safebrowsing.downloads.remote.enabled",	false);

// PREF: Disable Pocket
// https://support.mozilla.org/en-US/kb/save-web-pages-later-pocket-firefox
// https://github.com/pyllyukko/user.js/issues/143
user_pref("browser.pocket.enabled",				false);
user_pref("extensions.pocket.enabled",				false);

// PREF: Disable "Recommended by Pocket" in Firefox Quantum
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories",	false);

/******************************************************************************
 * SECTION: Automatic connections                                             *
 ******************************************************************************/

// PREF: Limit the connection keep-alive timeout to 15 seconds (disabled)
// https://github.com/pyllyukko/user.js/issues/387
// http://kb.mozillazine.org/Network.http.keep-alive.timeout
// https://httpd.apache.org/docs/current/mod/core.html#keepalivetimeout
//user_pref("network.http.keep-alive.timeout",			15);

// PREF: Disable prefetching of <link rel="next"> URLs
// http://kb.mozillazine.org/Network.prefetch-next
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Link_prefetching_FAQ#Is_there_a_preference_to_disable_link_prefetching.3F
user_pref("network.prefetch-next",				false);

// PREF: Disable DNS prefetching
// http://kb.mozillazine.org/Network.dns.disablePrefetch
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Controlling_DNS_prefetching
user_pref("network.dns.disablePrefetch",			true);
user_pref("network.dns.disablePrefetchFromHTTPS",		true);

// PREF: Disable the predictive service (Necko)
// https://wiki.mozilla.org/Privacy/Reviews/Necko
user_pref("network.predictor.enabled",				false);

// PREF: Reject .onion hostnames before passing the to DNS
// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
// RFC 7686
user_pref("network.dns.blockDotOnion",				true);

// PREF: Disable search suggestions in the search bar
// http://kb.mozillazine.org/Browser.search.suggest.enabled
user_pref("browser.search.suggest.enabled",			false);

// PREF: Disable "Show search suggestions in location bar results"
user_pref("browser.urlbar.suggest.searches",			false);
// PREF: When using the location bar, don't suggest URLs from browsing history
user_pref("browser.urlbar.suggest.history",			true);

// PREF: Disable SSDP
// https://bugzilla.mozilla.org/show_bug.cgi?id=1111967
user_pref("browser.casting.enabled",				false);

// PREF: Disable automatic downloading of OpenH264 codec
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_media-capabilities
// https://andreasgal.com/2014/10/14/openh264-now-in-firefox/
user_pref("media.gmp-gmpopenh264.enabled",			false);
user_pref("media.gmp-manager.url",				"");

// PREF: Disable speculative pre-connections
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_speculative-pre-connections
// https://bugzilla.mozilla.org/show_bug.cgi?id=814169
user_pref("network.http.speculative-parallel-limit",		0);

// PREF: Disable downloading homepage snippets/messages from Mozilla
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
// https://wiki.mozilla.org/Firefox/Projects/Firefox_Start/Snippet_Service
user_pref("browser.aboutHomeSnippets.updateUrl",		"");

// PREF: Never check updates for search engines
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
user_pref("browser.search.update",				false);

// PREF: Disable automatic captive portal detection (Firefox >= 52.0)
// https://support.mozilla.org/en-US/questions/1157121
user_pref("network.captive-portal-service.enabled",		false);

/******************************************************************************
 * SECTION: HTTP                                                              *
 ******************************************************************************/

// PREF: Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1",	false);
// it is still allowed through HTTPS. uncomment the following to disable it completely.
//user_pref("network.negotiate-auth.allow-insecure-ntlm-v1-https",		false);

// PREF: Enable CSP 1.1 script-nonce directive support
// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
user_pref("security.csp.experimentalEnabled",			true);

// PREF: Enable Content Security Policy (CSP)
// https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
user_pref("security.csp.enable",				true);

// PREF: Enable Subresource Integrity
// https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
// https://wiki.mozilla.org/Security/Subresource_Integrity
user_pref("security.sri.enable",				true);

// PREF: DNT HTTP header (disabled)
// https://www.mozilla.org/en-US/firefox/dnt/
// https://en.wikipedia.org/wiki/Do_not_track_header
// https://dnt-dashboard.mozilla.org
// https://github.com/pyllyukko/user.js/issues/11
// NOTICE: Do No Track must be enabled manually
//user_pref("privacy.donottrackheader.enabled",		true);

// PREF: Send a referer header with the target URI as the source (disabled)
// https://bugzilla.mozilla.org/show_bug.cgi?id=822869
// https://github.com/pyllyukko/user.js/issues/227
// NOTICE-DISABLED: Spoofing referers breaks functionality on websites relying on authentic referer headers
// NOTICE-DISABLED: Spoofing referers breaks visualisation of 3rd-party sites on the Lightbeam addon
// NOTICE-DISABLED: Spoofing referers disables CSRF protection on some login pages not implementing origin-header/cookie+token based CSRF protection
// TODO: https://github.com/pyllyukko/user.js/issues/94, commented-out XOriginPolicy/XOriginTrimmingPolicy = 2 prefs
user_pref("network.http.referer.spoofSource",			false);

// PREF: Don't send referer headers when following links across different domains
// https://github.com/pyllyukko/user.js/issues/227
// https://github.com/pyllyukko/user.js/issues/328
// https://feeding.cloud.geek.nz/posts/tweaking-referrer-for-privacy-in-firefox/
user_pref("network.http.referer.XOriginPolicy",		2);

// PREF: Accept Only 1st Party Cookies
// http://kb.mozillazine.org/Network.cookie.cookieBehavior#1
// NOTICE: Blocking 3rd-party cookies breaks a number of payment gateways
// CIS 2.5.1
user_pref("network.cookie.cookieBehavior",			1);

// PREF: Enable first-party isolation
// https://bugzilla.mozilla.org/show_bug.cgi?id=1299996
// https://bugzilla.mozilla.org/show_bug.cgi?id=1260931
// https://wiki.mozilla.org/Security/FirstPartyIsolation
// NOTICE: First-party isolation breaks Microsoft Teams
// NOTICE: First-party isolation causes HTTP basic auth to ask for credentials for every new tab (see #425)
user_pref("privacy.firstparty.isolate",				true);

// PREF: Make sure that third-party cookies (if enabled) never persist beyond the session.
// https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
// http://kb.mozillazine.org/Network.cookie.thirdparty.sessionOnly
// https://developer.mozilla.org/en-US/docs/Cookies_Preferences_in_Mozilla#network.cookie.thirdparty.sessionOnly
user_pref("network.cookie.thirdparty.sessionOnly",		true);

// PREF: Spoof User-agent (disabled)
//user_pref("general.useragent.override",				"Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0");
//user_pref("general.appname.override",				"Netscape");
//user_pref("general.appversion.override",			"5.0 (Windows)");
//user_pref("general.platform.override",				"Win32");
//user_pref("general.oscpu.override",				"Windows NT 6.1");

/*******************************************************************************
 * SECTION: Caching                                                            *
 ******************************************************************************/

// PREF: Permanently enable private browsing mode
// https://support.mozilla.org/en-US/kb/Private-Browsing
// https://wiki.mozilla.org/PrivateBrowsing
// NOTICE: You can not view or inspect cookies when in private browsing: https://bugzilla.mozilla.org/show_bug.cgi?id=823941
// NOTICE: When Javascript is enabled, Websites can detect use of Private Browsing mode
// NOTICE: Private browsing breaks Kerberos authentication
// NOTICE: Disables "Containers" functionality (see below)
// NOTICE: "Always use private browsing mode" (browser.privatebrowsing.autostart) disables the possibility to use password manager: https://support.mozilla.org/en-US/kb/usernames-and-passwords-are-not-saved#w_private-browsing
user_pref("browser.privatebrowsing.autostart",			false);

// PREF: Do not download URLs for the offline cache
// http://kb.mozillazine.org/Browser.cache.offline.enable
user_pref("browser.cache.offline.enable",			false);

// PREF: Clear history when Firefox closes
// https://support.mozilla.org/en-US/kb/Clear%20Recent%20History#w_how-do-i-make-firefox-clear-my-history-automatically
// NOTICE: Installing user.js will remove your browsing history, caches and local storage.
// NOTICE: Installing user.js **will remove your saved passwords** (https://github.com/pyllyukko/user.js/issues/27)
// NOTICE: Clearing open windows on Firefox exit causes 2 windows to open when Firefox starts https://bugzilla.mozilla.org/show_bug.cgi?id=1334945
user_pref("privacy.sanitize.sanitizeOnShutdown",		true);
user_pref("privacy.clearOnShutdown.cache",			true);
user_pref("privacy.clearOnShutdown.cookies",			true);
user_pref("privacy.clearOnShutdown.downloads",			true);
user_pref("privacy.clearOnShutdown.formdata",			true);
user_pref("privacy.clearOnShutdown.history",			false);
user_pref("privacy.clearOnShutdown.offlineApps",		true);
user_pref("privacy.clearOnShutdown.sessions",			false);
user_pref("privacy.clearOnShutdown.openWindows",		false);

// PREF: Set time range to "Everything" as default in "Clear Recent History"
user_pref("privacy.sanitize.timeSpan",				0);

// PREF: Clear everything but "Site Preferences" in "Clear Recent History"
user_pref("privacy.cpd.offlineApps",				true);
user_pref("privacy.cpd.cache",					true);
user_pref("privacy.cpd.cookies",				true);
user_pref("privacy.cpd.downloads",				true);
user_pref("privacy.cpd.formdata",				true);
user_pref("privacy.cpd.history",				true);
user_pref("privacy.cpd.sessions",				true);

// PREF: Don't remember browsing history
user_pref("places.history.enabled",				true);

// PREF: Disable disk cache
// http://kb.mozillazine.org/Browser.cache.disk.enable
user_pref("browser.cache.disk.enable",				false);

// PREF: Disable memory cache (disabled)
// http://kb.mozillazine.org/Browser.cache.memory.enable
//user_pref("browser.cache.memory.enable",		false);

// PREF: Disable Caching of SSL Pages
// CIS Version 1.2.0 October 21st, 2011 2.5.8
// http://kb.mozillazine.org/Browser.cache.disk_cache_ssl
user_pref("browser.cache.disk_cache_ssl",			false);

// PREF: Disable download history
// CIS Version 1.2.0 October 21st, 2011 2.5.5
user_pref("browser.download.manager.retention",			0);

// PREF: Disable password manager (use an external password manager!)
// CIS Version 1.2.0 October 21st, 2011 2.5.2
user_pref("signon.rememberSignons",				false);

// PREF: Disable form autofill, don't save information entered in web page forms and the Search Bar
user_pref("browser.formfill.enable",				false);

// PREF: Cookies expires at the end of the session (when the browser closes)
// http://kb.mozillazine.org/Network.cookie.lifetimePolicy#2
user_pref("network.cookie.lifetimePolicy",			2);

// PREF: Require manual intervention to autofill known username/passwords sign-in forms
// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms",				false);

// PREF: Disable formless login capture
// https://bugzilla.mozilla.org/show_bug.cgi?id=1166947
user_pref("signon.formlessCapture.enabled",			false);

// PREF: When username/password autofill is enabled, still disable it on non-HTTPS sites
// https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
user_pref("signon.autofillForms.http",				false);

// PREF: Show in-content login form warning UI for insecure login fields
// https://hg.mozilla.org/integration/mozilla-inbound/rev/f0d146fe7317
user_pref("security.insecure_field_warning.contextual.enabled", true);

// PREF: Disable the password manager for pages with autocomplete=off (disabled)
// https://bugzilla.mozilla.org/show_bug.cgi?id=956906
// OWASP ASVS V9.1
// Does not prevent any kind of auto-completion (see browser.formfill.enable, signon.autofillForms)
//user_pref("signon.storeWhenAutocompleteOff",			false);

// PREF: Delete Search and Form History
// CIS Version 1.2.0 October 21st, 2011 2.5.6
user_pref("browser.formfill.expire_days",			0);

// PREF: Clear SSL Form Session Data
// http://kb.mozillazine.org/Browser.sessionstore.privacy_level#2
// Store extra session data for unencrypted (non-HTTPS) sites only.
// CIS Version 1.2.0 October 21st, 2011 2.5.7
// NOTE: CIS says 1, we use 2
user_pref("browser.sessionstore.privacy_level",			2);

// PREF: Delete temporary files on exit
// https://bugzilla.mozilla.org/show_bug.cgi?id=238789
user_pref("browser.helperApps.deleteTempFileOnExit",		true);

// PREF: Do not create screenshots of visited pages (relates to the "new tab page" feature)
// https://support.mozilla.org/en-US/questions/973320
// https://developer.mozilla.org/en-US/docs/Mozilla/Preferences/Preference_reference/browser.pagethumbnails.capturing_disabled
user_pref("browser.pagethumbnails.capturing_disabled",		true);

// PREF: Don't fetch and permanently store favicons for Windows .URL shortcuts created by drag and drop
// NOTICE: .URL shortcut files will be created with a generic icon
// Favicons are stored as .ico files in $profile_dir\shortcutCache
user_pref("browser.shell.shortcutFavicons",					false);

// PREF: Disable bookmarks backups (default: 15)
// http://kb.mozillazine.org/Browser.bookmarks.max_backups
user_pref("browser.bookmarks.max_backups", 0);

// PREF: Export bookmarks to HTML automatically when closing Firefox (disabled)
// https://support.mozilla.org/en-US/questions/1176242
//user_pref("browser.bookmarks.autoExportHTML", 				true);
//user_pref("browser.bookmarks.file",	'/path/to/bookmarks-export.html');

/*******************************************************************************
 * SECTION: UI related                                                         *
 *******************************************************************************/

// PREF: Enable insecure password warnings (login forms in non-HTTPS pages)
// https://blog.mozilla.org/tanvi/2016/01/28/no-more-passwords-over-http-please/
// https://bugzilla.mozilla.org/show_bug.cgi?id=1319119
// https://bugzilla.mozilla.org/show_bug.cgi?id=1217156
user_pref("security.insecure_password.ui.enabled",		true);

// PREF: Disable right-click menu manipulation via JavaScript (disabled)
//user_pref("dom.event.contextmenu.enabled",		false);

// PREF: Disable "Are you sure you want to leave this page?" popups on page close
// https://support.mozilla.org/en-US/questions/1043508
// NOTICE: disabling "beforeunload" events may lead to losing data entered in web forms
// Does not prevent JS leaks of the page close event.
// https://developer.mozilla.org/en-US/docs/Web/Events/beforeunload
//user_pref("dom.disable_beforeunload",    true);

// PREF: Disable Downloading on Desktop
// CIS 2.3.2
user_pref("browser.download.folderList",			2);

// PREF: Always ask the user where to download
// https://developer.mozilla.org/en/Download_Manager_preferences (obsolete)
user_pref("browser.download.useDownloadDir",			false);

// PREF: Disable the "new tab page" feature and show a blank tab instead
// https://wiki.mozilla.org/Privacy/Reviews/New_Tab
// https://support.mozilla.org/en-US/kb/new-tab-page-show-hide-and-customize-top-sites#w_how-do-i-turn-the-new-tab-page-off
user_pref("browser.newtabpage.enabled",				false);
user_pref("browser.newtab.url",					"about:blank");

// PREF: Disable Snippets
// https://wiki.mozilla.org/Firefox/Projects/Firefox_Start/Snippet_Service
// https://support.mozilla.org/en-US/kb/snippets-firefox-faq
user_pref("browser.newtabpage.activity-stream.feeds.snippets",	false);

// PREF: Disable Activity Stream
// https://wiki.mozilla.org/Firefox/Activity_Stream
user_pref("browser.newtabpage.activity-stream.enabled",		false);

// PREF: Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
// TODO: deprecated? not in DXR, some dead links
user_pref("browser.newtabpage.enhanced",			false);
user_pref("browser.newtab.preload",				false);
user_pref("browser.newtabpage.directory.ping",			"");
user_pref("browser.newtabpage.directory.source",		"data:text/plain,{}");

// PREF: Enable Auto Notification of Outdated Plugins (Firefox < 50)
// https://wiki.mozilla.org/Firefox3.6/Plugin_Update_Awareness_Security_Review
// CIS Version 1.2.0 October 21st, 2011 2.1.2
// https://hg.mozilla.org/mozilla-central/rev/304560
user_pref("plugins.update.notifyUser",				true);

// PREF: Force Punycode for Internationalized Domain Names
// http://kb.mozillazine.org/Network.IDN_show_punycode
// https://www.xudongz.com/blog/2017/idn-phishing/
// https://wiki.mozilla.org/IDN_Display_Algorithm
// https://en.wikipedia.org/wiki/IDN_homograph_attack
// https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6
user_pref("network.IDN_show_punycode",				true);

// PREF: Disable inline autocomplete in URL bar
// http://kb.mozillazine.org/Inline_autocomplete
user_pref("browser.urlbar.autoFill",				true);
user_pref("browser.urlbar.autoFill.typed",			true);

// PREF: Disable CSS :visited selectors
// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// https://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled",			false);

// PREF: Disable URL bar autocomplete and history/bookmarks suggestions dropdown
// http://kb.mozillazine.org/Disabling_autocomplete_-_Firefox#Firefox_3.5
user_pref("browser.urlbar.autocomplete.enabled",		false);

// PREF: Do not check if Firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser",			false);

// PREF: When password manager is enabled, lock the password storage periodically
// CIS Version 1.2.0 October 21st, 2011 2.5.3 Disable Prompting for Credential Storage
user_pref("security.ask_for_password",				2);

// PREF: Lock the password storage every 1 minutes (default: 30)
user_pref("security.password_lifetime",				1);

// PREF: Display a notification bar when websites offer data for offline use
// http://kb.mozillazine.org/Browser.offline-apps.notify
user_pref("browser.offline-apps.notify",			true);

/******************************************************************************
 * SECTION: Cryptography                                                      *
 ******************************************************************************/

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
user_pref("network.stricttransportsecurity.preloadlist",	true);

// PREF: Enable Online Certificate Status Protocol
// https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol
// https://www.imperialviolet.org/2014/04/19/revchecking.html
// https://www.maikel.pro/blog/current-state-certificate-revocation-crls-ocsp/
// https://wiki.mozilla.org/CA:RevocationPlan
// https://wiki.mozilla.org/CA:ImprovingRevocation
// https://wiki.mozilla.org/CA:OCSP-HardFail
// https://news.netcraft.com/archives/2014/04/24/certificate-revocation-why-browsers-remain-affected-by-heartbleed.html
// https://news.netcraft.com/archives/2013/04/16/certificate-revocation-and-the-performance-of-ocsp.html
// NOTICE: OCSP leaks your IP and domains you visit to the CA when OCSP Stapling is not available on visited host
// NOTICE: OCSP is vulnerable to replay attacks when nonce is not configured on the OCSP responder
// NOTICE: OCSP adds latency (performance)
// NOTICE: Short-lived certificates are not checked for revocation (security.pki.cert_short_lifetime_in_days, default:10)
// CIS Version 1.2.0 October 21st, 2011 2.2.4
user_pref("security.OCSP.enabled",				1);

// PREF: Enable OCSP Stapling support
// https://en.wikipedia.org/wiki/OCSP_stapling
// https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/
// https://www.digitalocean.com/community/tutorials/how-to-configure-ocsp-stapling-on-apache-and-nginx
user_pref("security.ssl.enable_ocsp_stapling",			true);

// PREF: Enable OCSP Must-Staple support (Firefox >= 45)
// https://blog.mozilla.org/security/2015/11/23/improving-revocation-ocsp-must-staple-and-short-lived-certificates/
// https://www.entrust.com/ocsp-must-staple/
// https://github.com/schomery/privacy-settings/issues/40
// NOTICE: Firefox falls back on plain OCSP when must-staple is not configured on the host certificate
user_pref("security.ssl.enable_ocsp_must_staple",		true);

// PREF: Require a valid OCSP response for OCSP enabled certificates
// https://groups.google.com/forum/#!topic/mozilla.dev.security/n1G-N2-HTVA
// Disabling this will make OCSP bypassable by MitM attacks suppressing OCSP responses
// NOTICE: `security.OCSP.require` will make the connection fail when the OCSP responder is unavailable
// NOTICE: `security.OCSP.require` is known to break browsing on some [captive portals](https://en.wikipedia.org/wiki/Captive_portal)
user_pref("security.OCSP.require",				true);

// PREF: Disable TLS Session Tickets
// https://www.blackhat.com/us-13/briefings.html#NextGen
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-Slides.pdf
// https://media.blackhat.com/us-13/US-13-Daigniere-TLS-Secrets-WP.pdf
// https://bugzilla.mozilla.org/show_bug.cgi?id=917049
// https://bugzilla.mozilla.org/show_bug.cgi?id=967977
user_pref("security.ssl.disable_session_identifiers",		true);

// PREF: Only allow TLS 1.[0-3]
// http://kb.mozillazine.org/Security.tls.version.*
// 1 = TLS 1.0 is the minimum required / maximum supported encryption protocol. (This is the current default for the maximum supported version.)
// 2 = TLS 1.1 is the minimum required / maximum supported encryption protocol.
// 3 = TLS 1.2 is the minimum required / maximum supported encryption protocol.
// 4 = TLS 1.3 is the minimum required / maximum supported encryption protocol.
user_pref("security.tls.version.min",				3);
user_pref("security.tls.version.max",				4);

// PREF: Disable insecure TLS version fallback
// https://bugzilla.mozilla.org/show_bug.cgi?id=1084025
// https://github.com/pyllyukko/user.js/pull/206#issuecomment-280229645
user_pref("security.tls.version.fallback-limit",		3);

// PREF: Enforce Public Key Pinning
// https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
// https://wiki.mozilla.org/SecurityEngineering/Public_Key_Pinning
// "2. Strict. Pinning is always enforced."
user_pref("security.cert_pinning.enforcement_level",		2);

// PREF: Disallow SHA-1
// https://bugzilla.mozilla.org/show_bug.cgi?id=1302140
// https://shattered.io/
user_pref("security.pki.sha1_enforcement_level",		1);

// PREF: Warn the user when server doesn't support RFC 5746 ("safe" renegotiation)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.treat_unsafe_negotiation_as_broken
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
user_pref("security.ssl.treat_unsafe_negotiation_as_broken",	true);

// PREF: Disallow connection to servers not supporting safe renegotiation (disabled)
// https://wiki.mozilla.org/Security:Renegotiation#security.ssl.require_safe_negotiation
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2009-3555
// TODO: `security.ssl.require_safe_negotiation` is more secure but makes browsing next to impossible (2012-2014-... - `ssl_error_unsafe_negotiation` errors), so is left disabled
user_pref("security.ssl.require_safe_negotiation",		true);

// PREF: Disable automatic reporting of TLS connection errors
// https://support.mozilla.org/en-US/kb/certificate-pinning-reports
// we could also disable security.ssl.errorReporting.enabled, but I think it's
// good to leave the option to report potentially malicious sites if the user
// chooses to do so.
// you can test this at https://pinningtest.appspot.com/
user_pref("security.ssl.errorReporting.automatic",		false);

// PREF: Pre-populate the current URL but do not pre-fetch the certificate in the "Add Security Exception" dialog
// http://kb.mozillazine.org/Browser.ssl_override_behavior
// https://github.com/pyllyukko/user.js/issues/210
user_pref("browser.ssl_override_behavior",			1);

// PREF: Encrypted SNI (when TRR is enabled)
// https://www.cloudflare.com/ssl/encrypted-sni/
// https://wiki.mozilla.org/Trusted_Recursive_Resolver#ESNI
// https://en.wikipedia.org/wiki/Server_Name_Indication#Security_implications_(ESNI)
user_pref("network.security.esni.enabled",			true);

/******************************************************************************
 * SECTION: Cipher suites                                                     *
 ******************************************************************************/

// PREF: Disable null ciphers
user_pref("security.ssl3.rsa_null_sha",				false);
user_pref("security.ssl3.rsa_null_md5",				false);
user_pref("security.ssl3.ecdhe_rsa_null_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha",			false);
user_pref("security.ssl3.ecdh_rsa_null_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha",			false);

// PREF: Disable SEED cipher
// https://en.wikipedia.org/wiki/SEED
user_pref("security.ssl3.rsa_seed_sha",				false);

// PREF: Disable 40/56/128-bit ciphers
// 40-bit ciphers
user_pref("security.ssl3.rsa_rc4_40_md5",			false);
user_pref("security.ssl3.rsa_rc2_40_md5",			false);
// 56-bit ciphers
user_pref("security.ssl3.rsa_1024_rc4_56_sha",			false);
// 128-bit ciphers
user_pref("security.ssl3.rsa_camellia_128_sha",			false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha",			false);

// PREF: Disable RC4
// https://developer.mozilla.org/en-US/Firefox/Releases/38#Security
// https://bugzilla.mozilla.org/show_bug.cgi?id=1138882
// https://rc4.io/
// https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2566
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha",			false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha",		false);
user_pref("security.ssl3.rsa_rc4_128_md5",			false);
user_pref("security.ssl3.rsa_rc4_128_sha",			false);
user_pref("security.tls.unrestricted_rc4_fallback",		false);

// PREF: Disable 3DES (effective key size is < 128)
// https://en.wikipedia.org/wiki/3des#Security
// http://en.citizendium.org/wiki/Meet-in-the-middle_attack
// http://www-archive.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
user_pref("security.ssl3.dhe_dss_des_ede3_sha",			false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha",		false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha",		false);
user_pref("security.ssl3.rsa_des_ede3_sha",			false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha",		false);

// PREF: Disable ciphers with ECDH (non-ephemeral)
user_pref("security.ssl3.ecdh_rsa_aes_256_sha",			false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha",		false);

// PREF: Disable 256 bits ciphers without PFS
user_pref("security.ssl3.rsa_camellia_256_sha",			false);

// PREF: Enable GCM ciphers (TLSv1.2 only)
// https://en.wikipedia.org/wiki/Galois/Counter_Mode
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256",	true); // 0xc02b
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256",		true); // 0xc02f

// PREF: Enable ChaCha20 and Poly1305 (Firefox >= 47)
// https://www.mozilla.org/en-US/firefox/47.0/releasenotes/
// https://tools.ietf.org/html/rfc7905
// https://bugzilla.mozilla.org/show_bug.cgi?id=917571
// https://bugzilla.mozilla.org/show_bug.cgi?id=1247860
// https://cr.yp.to/chacha.html
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256",	true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256",	true);

// PREF: Disable ciphers susceptible to the logjam attack
// https://weakdh.org/
user_pref("security.ssl3.dhe_rsa_camellia_256_sha",		false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha",			false);

// PREF: Disable ciphers with DSA (max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha",			false);
user_pref("security.ssl3.dhe_dss_aes_256_sha",			false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha",		false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha",		false);

// PREF: Ciphers with CBC & SHA-1 (disabled)
user_pref("security.ssl3.rsa_aes_256_sha",			false); // 0x35
user_pref("security.ssl3.rsa_aes_128_sha",			false); // 0x2f
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha",		false); // 0xc014
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha",		false); // 0xc00a

////////////
// Custom //
////////////

// https://github.com/pyllyukko/user.js
// https://github.com/ghacksuserjs/ghacks-user.js
// https://www.ssi.gouv.fr/uploads/2015/01/NP_NavigateurSecurise_FireFox_1-1.pdf

//////////////////////
// Custom/Usability //
//////////////////////

// Warn when entering in about:config
user_pref("general.warnOnAboutConfig", false);
// Startup page (0=blank, 1=home, 2=last visited page, 3=resume previous session)
user_pref("browser.startup.page", 3);
// Navigate tabs by last use
user_pref("browser.ctrlTab.previews", false);
// Home page (about:home, about:blank, URL)
user_pref("browser.startup.homepage", "about:blank");
// How to open links that would normally open in a new window (1: current tab, 2: new window, 3: new tab)
user_pref("browser.link.open_newwindow", 3);
// Load a new tab without switching to it
user_pref("browser.tabs.loadInBackground", true);
// Spellchecker (0: disabled, 1: multi-line, 2: multi-line & single-line)
user_pref("layout.spellcheckDefault", 1);
// Disable accessibility services
user_pref("accessibility.force_disabled", 1);

////////////////////////
// Custom/Geolocation //
////////////////////////

// Default permission for geolocation (0=always ask (default), 1=allow, 2=block)
user_pref("permissions.default.geo", 2);

///////////////////
// Custom/Search //
///////////////////

// Default search engine
user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
// Search suggestions
user_pref("browser.urlbar.searchSuggestionsChoice", false);
// Disable location-specific search
// DEFAULT: https://search.services.mozilla.com/1/%APP%/%VERSION%/%CHANNEL%/%LOCALE%/%REGION%/%DISTRIBUTION%/%DISTRIBUTION_VERSION%
user_pref("browser.search.geoSpecificDefaults.url", "");
// Locale (Use OS locale if empty)
// Don't use OS locale
user_pref("intl.locale.requested", "en-US");

////////////////////
// Custom/Plugins //
////////////////////

// Default plugin state (0: disabled, 1: ask, 2: active)
user_pref("plugin.default.state", 0);
user_pref("plugin.defaultXpi.state", 0);
// Click to play
// https://jjacky.com/2013-10-24-restore-click-to-activate-per-element-in-firefox/
user_pref("plugin.sessionPermissionNow.intervalInMinutes", 0);
// DRM (Encryption Media Extension)
user_pref("media.eme.enabled", true);

////////////////////
// Custom/Privacy //
////////////////////

// Disable sending reports of tab crashes
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit", false); // (FF51-57)
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false); // (FF58+)
// Disable data sharing (FF58+)
user_pref("browser.safebrowsing.provider.google4.dataSharing.enabled", false);
// DNT
user_pref("privacy.donottrackheader.enabled", false);
// NORMANDY (https://github.com/mozilla/normandy)
user_pref("app.normandy.enabled", false);
// Activity stream
user_pref("browser.library.activity-stream.enabled", false);
// Search
user_pref("browser.newtabpage.activity-stream.prerender", false);
user_pref("browser.newtabpage.activity-stream.showSearch", false);
// Most visited websites
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
// Highlights
user_pref("browser.newtabpage.activity-stream.feeds.section.highlights", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeBookmarks", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeDownloads", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includeVisited", false);
// Snippets
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
// SSL Error reporting
user_pref("security.ssl.errorReporting.enabled", false);
user_pref("security.ssl.errorReporting.url", "");
// Built-in tracking blocker
user_pref("browser.contentblocking.category", "custom");
// Block cryptominers
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
// Block fingerprinting
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

/////////////////////////////
// Custom/Password & forms //
/////////////////////////////

// Form autofill
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.available", "off");
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.heuristics.enabled", false);

/////////////////////
// Custom/Security //
/////////////////////

// Disable HTTP-Authentication request from cross-origin images
user_pref("network.auth.subresource-img-cross-origin-http-auth-allow", false);
// TLS 1.3 0-RTT (speedup but security concern)
user_pref("security.tls.enable_0rtt_data", false);
// More informations on certificate issues
user_pref("browser.xul.error_pages.expert_bad_cert", true);
// Notify about insecure (HTTP) sites
user_pref("security.insecure_connection_icon.enabled", true);
user_pref("security.insecure_connection_icon.pbmode.enabled", true);
user_pref("security.insecure_connection_text.enabled", true);
user_pref("security.insecure_connection_text.pbmode.enabled", true);

/////////////////
// Custom/Sync //
/////////////////

user_pref("services.sync.prefs.sync.accessibility.force_disabled", true);
user_pref("services.sync.prefs.sync.app.normandy.enabled", true);
user_pref("services.sync.prefs.sync.app.shield.optoutstudies.enabled", true);
user_pref("services.sync.prefs.sync.app.update.enabled", true);
user_pref("services.sync.prefs.sync.beacon.enabled", true);
user_pref("services.sync.prefs.sync.breakpad.reportURL", true);
user_pref("services.sync.prefs.sync.browser.aboutHomeSnippets.updateUrl", true);
user_pref("services.sync.prefs.sync.browser.bookmarks.max_backups", true);
user_pref("services.sync.prefs.sync.browser.cache.disk.enable", true);
user_pref("services.sync.prefs.sync.browser.cache.disk_cache_ssl", true);
user_pref("services.sync.prefs.sync.browser.cache.offline.enable", true);
user_pref("services.sync.prefs.sync.browser.casting.enabled", true);
user_pref("services.sync.prefs.sync.browser.contentblocking.category", true);
user_pref("services.sync.prefs.sync.browser.crashReports.unsubmittedCheck.autoSubmit", true);
user_pref("services.sync.prefs.sync.browser.crashReports.unsubmittedCheck.autoSubmit2", true);
user_pref("services.sync.prefs.sync.browser.crashReports.unsubmittedCheck.enabled", true);
user_pref("services.sync.prefs.sync.browser.ctrlTab.previews", true);
user_pref("services.sync.prefs.sync.browser.discovery.enabled", true);
user_pref("services.sync.prefs.sync.browser.display.use_document_fonts", true);
user_pref("services.sync.prefs.sync.browser.download.folderList", true);
user_pref("services.sync.prefs.sync.browser.download.manager.retention", true);
user_pref("services.sync.prefs.sync.browser.download.useDownloadDir", true);
user_pref("services.sync.prefs.sync.browser.fixup.alternate.enabled", true);
user_pref("services.sync.prefs.sync.browser.fixup.hide_user_pass", true);
user_pref("services.sync.prefs.sync.browser.formfill.enable", true);
user_pref("services.sync.prefs.sync.browser.formfill.expire_days", true);
user_pref("services.sync.prefs.sync.browser.helperApps.deleteTempFileOnExit", true);
user_pref("services.sync.prefs.sync.browser.library.activity-stream.enabled", true);
user_pref("services.sync.prefs.sync.browser.link.open_newwindow", true);
user_pref("services.sync.prefs.sync.browser.newtab.preload", true);
user_pref("services.sync.prefs.sync.browser.newtab.url", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.asrouter.userprefs.cfr", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.enabled", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.feeds.section.highlights", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.feeds.section.topstories", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.feeds.snippets", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.feeds.snippets", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.feeds.topsites", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.prerender", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includeBookmarks", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includeDownloads", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includePocket", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.section.highlights.includeVisited", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.activity-stream.showSearch", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.directory.ping", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.directory.source", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.enabled", true);
user_pref("services.sync.prefs.sync.browser.newtabpage.enhanced", true);
user_pref("services.sync.prefs.sync.browser.offline-apps.notify", true);
user_pref("services.sync.prefs.sync.browser.pagethumbnails.capturing_disabled", true);
user_pref("services.sync.prefs.sync.browser.pocket.enabled", true);
user_pref("services.sync.prefs.sync.browser.privatebrowsing.autostart", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.blockedURIs.enabled", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.downloads.remote.enabled", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.enabled", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.malware.enabled", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.phishing.enabled", true);
user_pref("services.sync.prefs.sync.browser.safebrowsing.provider.google4.dataSharing.enabled", true);
user_pref("services.sync.prefs.sync.browser.search.countryCode", true);
user_pref("services.sync.prefs.sync.browser.search.geoSpecificDefaults", true);
user_pref("services.sync.prefs.sync.browser.search.geoSpecificDefaults.url", true);
user_pref("services.sync.prefs.sync.browser.search.geoip.url", true);
user_pref("services.sync.prefs.sync.browser.search.region", true);
user_pref("services.sync.prefs.sync.browser.search.suggest.enabled", true);
user_pref("services.sync.prefs.sync.browser.search.update", true);
user_pref("services.sync.prefs.sync.browser.selfsupport.url", true);
user_pref("services.sync.prefs.sync.browser.send_pings", true);
user_pref("services.sync.prefs.sync.browser.send_pings.require_same_host", true);
user_pref("services.sync.prefs.sync.browser.sessionstore.privacy_level", true);
user_pref("services.sync.prefs.sync.browser.shell.checkDefaultBrowser", true);
user_pref("services.sync.prefs.sync.browser.shell.shortcutFavicons", true);
user_pref("services.sync.prefs.sync.browser.ssl_override_behavior", true);
user_pref("services.sync.prefs.sync.browser.startup.homepage", true);
user_pref("services.sync.prefs.sync.browser.startup.homepage_override.buildID", true);
user_pref("services.sync.prefs.sync.browser.startup.page", true);
user_pref("services.sync.prefs.sync.browser.tabs.crashReporting.sendReport", true);
user_pref("services.sync.prefs.sync.browser.tabs.loadInBackground", true);
user_pref("services.sync.prefs.sync.browser.uitour.enabled", true);
user_pref("services.sync.prefs.sync.browser.urlbar.autoFill", true);
user_pref("services.sync.prefs.sync.browser.urlbar.autoFill.typed", true);
user_pref("services.sync.prefs.sync.browser.urlbar.autocomplete.enabled", true);
user_pref("services.sync.prefs.sync.browser.urlbar.filter.javascript", true);
user_pref("services.sync.prefs.sync.browser.urlbar.placeholderName", true);
user_pref("services.sync.prefs.sync.browser.urlbar.searchSuggestionsChoice", true);
user_pref("services.sync.prefs.sync.browser.urlbar.suggest.history", true);
user_pref("services.sync.prefs.sync.browser.urlbar.suggest.searches", true);
user_pref("services.sync.prefs.sync.browser.urlbar.trimURLs", true);
user_pref("services.sync.prefs.sync.browser.xul.error_pages.expert_bad_cert", true);
user_pref("services.sync.prefs.sync.camera.control.face_detection.enabled", true);
user_pref("services.sync.prefs.sync.clipboard.autocopy", true);
user_pref("services.sync.prefs.sync.datareporting.healthreport.service.enabled", true);
user_pref("services.sync.prefs.sync.datareporting.healthreport.uploadEnabled", true);
user_pref("services.sync.prefs.sync.datareporting.policy.dataSubmissionEnabled", true);
user_pref("services.sync.prefs.sync.device.sensors.enabled", true);
user_pref("services.sync.prefs.sync.devtools.chrome.enabled", true);
user_pref("services.sync.prefs.sync.devtools.debugger.force-local", true);
user_pref("services.sync.prefs.sync.devtools.debugger.remote-enabled", true);
user_pref("services.sync.prefs.sync.devtools.webide.autoinstallADBHelper", true);
user_pref("services.sync.prefs.sync.devtools.webide.autoinstallFxdtAdapters", true);
user_pref("services.sync.prefs.sync.devtools.webide.enabled", true);
user_pref("services.sync.prefs.sync.dom.allow_cut_copy", true);
user_pref("services.sync.prefs.sync.dom.archivereader.enabled", true);
user_pref("services.sync.prefs.sync.dom.battery.enabled", true);
user_pref("services.sync.prefs.sync.dom.enable_performance", true);
user_pref("services.sync.prefs.sync.dom.enable_resource_timing", true);
user_pref("services.sync.prefs.sync.dom.enable_user_timing", true);
user_pref("services.sync.prefs.sync.dom.event.clipboardevents.enabled", true);
user_pref("services.sync.prefs.sync.dom.flyweb.enabled", true);
user_pref("services.sync.prefs.sync.dom.gamepad.enabled", true);
user_pref("services.sync.prefs.sync.dom.ipc.plugins.flash.subprocess.crashreporter.enabled", true);
user_pref("services.sync.prefs.sync.dom.ipc.plugins.reportCrashURL", true);
user_pref("services.sync.prefs.sync.dom.maxHardwareConcurrency", true);
user_pref("services.sync.prefs.sync.dom.mozTCPSocket.enabled", true);
user_pref("services.sync.prefs.sync.dom.netinfo.enabled", true);
user_pref("services.sync.prefs.sync.dom.network.enabled", true);
user_pref("services.sync.prefs.sync.dom.serviceWorkers.enabled", true);
user_pref("services.sync.prefs.sync.dom.telephony.enabled", true);
user_pref("services.sync.prefs.sync.dom.vibrator.enabled", true);
user_pref("services.sync.prefs.sync.dom.vr.enabled", true);
user_pref("services.sync.prefs.sync.dom.webaudio.enabled", true);
user_pref("services.sync.prefs.sync.dom.webnotifications.enabled", true);
user_pref("services.sync.prefs.sync.experiments.enabled", true);
user_pref("services.sync.prefs.sync.experiments.manifest.uri", true);
user_pref("services.sync.prefs.sync.experiments.supported", true);
user_pref("services.sync.prefs.sync.extensions.blocklist.enabled", true);
user_pref("services.sync.prefs.sync.extensions.blocklist.url", true);
user_pref("services.sync.prefs.sync.extensions.formautofill.addresses.enabled", true);
user_pref("services.sync.prefs.sync.extensions.formautofill.available", true);
user_pref("services.sync.prefs.sync.extensions.formautofill.creditCards.enabled", true);
user_pref("services.sync.prefs.sync.extensions.formautofill.heuristics.enabled", true);
user_pref("services.sync.prefs.sync.extensions.getAddons.cache.enabled", true);
user_pref("services.sync.prefs.sync.extensions.pocket.enabled", true);
user_pref("services.sync.prefs.sync.extensions.shield-recipe-client.enabled", true);
user_pref("services.sync.prefs.sync.extensions.systemAddon.update.enabled", true);
user_pref("services.sync.prefs.sync.extensions.update.enabled", true);
user_pref("services.sync.prefs.sync.general.buildID.override", true);
user_pref("services.sync.prefs.sync.general.warnOnAboutConfig", true);
user_pref("services.sync.prefs.sync.geo.enabled", true);
user_pref("services.sync.prefs.sync.geo.wifi.logging.enabled", true);
user_pref("services.sync.prefs.sync.geo.wifi.uri", true);
user_pref("services.sync.prefs.sync.gfx.font_rendering.opentype_svg.enabled", true);
user_pref("services.sync.prefs.sync.intl.accept_languages", true);
user_pref("services.sync.prefs.sync.intl.locale.matchOS", true);
user_pref("services.sync.prefs.sync.intl.locale.requested", true);
user_pref("services.sync.prefs.sync.javascript.options.asmjs", true);
user_pref("services.sync.prefs.sync.javascript.options.wasm", true);
user_pref("services.sync.prefs.sync.javascript.use_us_english_locale", true);
user_pref("services.sync.prefs.sync.keyword.enabled", true);
user_pref("services.sync.prefs.sync.layout.css.visited_links_enabled", true);
user_pref("services.sync.prefs.sync.layout.spellcheckDefault", true);
user_pref("services.sync.prefs.sync.lightweightThemes.update.enabled", true);
user_pref("services.sync.prefs.sync.loop.logDomains", true);
user_pref("services.sync.prefs.sync.media.eme.enabled", true);
user_pref("services.sync.prefs.sync.media.getusermedia.audiocapture.enabled", true);
user_pref("services.sync.prefs.sync.media.getusermedia.screensharing.enabled", true);
user_pref("services.sync.prefs.sync.media.gmp-gmpopenh264.enabled", true);
user_pref("services.sync.prefs.sync.media.gmp-manager.url", true);
user_pref("services.sync.prefs.sync.media.navigator.enabled", true);
user_pref("services.sync.prefs.sync.media.navigator.video.enabled", true);
user_pref("services.sync.prefs.sync.media.peerconnection.enabled", true);
user_pref("services.sync.prefs.sync.media.peerconnection.ice.default_address_only", true);
user_pref("services.sync.prefs.sync.media.peerconnection.ice.no_host", true);
user_pref("services.sync.prefs.sync.media.video_stats.enabled", true);
user_pref("services.sync.prefs.sync.media.webspeech.recognition.enable", true);
user_pref("services.sync.prefs.sync.media.webspeech.synth.enabled", true);
user_pref("services.sync.prefs.sync.network.IDN_show_punycode", true);
user_pref("services.sync.prefs.sync.network.allow-experiments", true);
user_pref("services.sync.prefs.sync.network.auth.subresource-img-cross-origin-http-auth-allow", true);
user_pref("services.sync.prefs.sync.network.captive-portal-service.enabled", true);
user_pref("services.sync.prefs.sync.network.cookie.cookieBehavior", true);
user_pref("services.sync.prefs.sync.network.cookie.lifetimePolicy", true);
user_pref("services.sync.prefs.sync.network.cookie.thirdparty.sessionOnly", true);
user_pref("services.sync.prefs.sync.network.dns.blockDotOnion", true);
user_pref("services.sync.prefs.sync.network.dns.disablePrefetch", true);
user_pref("services.sync.prefs.sync.network.dns.disablePrefetchFromHTTPS", true);
user_pref("services.sync.prefs.sync.network.http.referer.spoofSource", true);
user_pref("services.sync.prefs.sync.network.http.speculative-parallel-limit", true);
user_pref("services.sync.prefs.sync.network.jar.open-unsafe-types", true);
user_pref("services.sync.prefs.sync.network.manage-offline-status", true);
user_pref("services.sync.prefs.sync.network.negotiate-auth.allow-insecure-ntlm-v1", true);
user_pref("services.sync.prefs.sync.network.predictor.enabled", true);
user_pref("services.sync.prefs.sync.network.prefetch-next", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose-all", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.about", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.blob", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.chrome", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.data", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.file", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.ftp", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.http", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.https", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.javascript", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.expose.moz-extension", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.about", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.blob", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.chrome", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.data", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.file", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.ftp", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.http", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.https", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.javascript", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.external.moz-extension", true);
user_pref("services.sync.prefs.sync.network.protocol-handler.warn-external-default", true);
user_pref("services.sync.prefs.sync.network.proxy.socks_remote_dns", true);
user_pref("services.sync.prefs.sync.network.stricttransportsecurity.preloadlist", true);
user_pref("services.sync.prefs.sync.network.trr.mode", true);
user_pref("services.sync.prefs.sync.network.trr.uri", true);
user_pref("services.sync.prefs.sync.pdfjs.disabled", true);
user_pref("services.sync.prefs.sync.permissions.default.geo", true);
user_pref("services.sync.prefs.sync.places.history.enabled", true);
user_pref("services.sync.prefs.sync.plugin.default.state", true);
user_pref("services.sync.prefs.sync.plugin.defaultXpi.state", true);
user_pref("services.sync.prefs.sync.plugin.sessionPermissionNow.intervalInMinutes", true);
user_pref("services.sync.prefs.sync.plugin.state.flash", true);
user_pref("services.sync.prefs.sync.plugin.state.java", true);
user_pref("services.sync.prefs.sync.plugin.state.libgnome-shell-browser-plugin", true);
user_pref("services.sync.prefs.sync.plugins.click_to_play", true);
user_pref("services.sync.prefs.sync.plugins.update.notifyUser", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.cache", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.cookies", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.downloads", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.formdata", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.history", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.offlineApps", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.openWindows", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.passwords", true);
user_pref("services.sync.prefs.sync.privacy.clearOnShutdown.sessions", true);
user_pref("services.sync.prefs.sync.privacy.cpd.cache", true);
user_pref("services.sync.prefs.sync.privacy.cpd.cookies", true);
user_pref("services.sync.prefs.sync.privacy.cpd.downloads", true);
user_pref("services.sync.prefs.sync.privacy.cpd.formdata", true);
user_pref("services.sync.prefs.sync.privacy.cpd.history", true);
user_pref("services.sync.prefs.sync.privacy.cpd.offlineApps", true);
user_pref("services.sync.prefs.sync.privacy.cpd.sessions", true);
user_pref("services.sync.prefs.sync.privacy.donottrackheader.enabled", true);
user_pref("services.sync.prefs.sync.privacy.firstparty.isolate", true);
user_pref("services.sync.prefs.sync.privacy.resistFingerprinting", true);
user_pref("services.sync.prefs.sync.privacy.sanitize.sanitizeOnShutdown", true);
user_pref("services.sync.prefs.sync.privacy.sanitize.timeSpan", true);
user_pref("services.sync.prefs.sync.privacy.trackingprotection.cryptomining.enabled", true);
user_pref("services.sync.prefs.sync.privacy.trackingprotection.enabled", true);
user_pref("services.sync.prefs.sync.privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("services.sync.prefs.sync.privacy.trackingprotection.pbmode.enabled", true);
user_pref("services.sync.prefs.sync.privacy.userContext.enabled", true);
user_pref("services.sync.prefs.sync.security.OCSP.enabled", true);
user_pref("services.sync.prefs.sync.security.OCSP.require", true);
user_pref("services.sync.prefs.sync.security.ask_for_password", true);
user_pref("services.sync.prefs.sync.security.cert_pinning.enforcement_level", true);
user_pref("services.sync.prefs.sync.security.csp.enable", true);
user_pref("services.sync.prefs.sync.security.csp.experimentalEnabled", true);
user_pref("services.sync.prefs.sync.security.dialog_enable_delay", true);
user_pref("services.sync.prefs.sync.security.fileuri.strict_origin_policy", true);
user_pref("services.sync.prefs.sync.security.insecure_connection_icon.enabled", true);
user_pref("services.sync.prefs.sync.security.insecure_connection_icon.pbmode.enabled", true);
user_pref("services.sync.prefs.sync.security.insecure_connection_text.enabled", true);
user_pref("services.sync.prefs.sync.security.insecure_connection_text.pbmode.enabled", true);
user_pref("services.sync.prefs.sync.security.insecure_field_warning.contextual.enabled", true);
user_pref("services.sync.prefs.sync.security.insecure_password.ui.enabled", true);
user_pref("services.sync.prefs.sync.security.mixed_content.block_active_content", true);
user_pref("services.sync.prefs.sync.security.mixed_content.block_display_content", true);
user_pref("services.sync.prefs.sync.security.password_lifetime", true);
user_pref("services.sync.prefs.sync.security.pki.sha1_enforcement_level", true);
user_pref("services.sync.prefs.sync.security.sri.enable", true);
user_pref("services.sync.prefs.sync.security.ssl.disable_session_identifiers", true);
user_pref("services.sync.prefs.sync.security.ssl.enable_ocsp_must_staple", true);
user_pref("services.sync.prefs.sync.security.ssl.enable_ocsp_stapling", true);
user_pref("services.sync.prefs.sync.security.ssl.errorReporting.automatic", true);
user_pref("services.sync.prefs.sync.security.ssl.errorReporting.enabled", true);
user_pref("services.sync.prefs.sync.security.ssl.errorReporting.url", true);
user_pref("services.sync.prefs.sync.security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_dss_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_dss_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_dss_camellia_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_dss_camellia_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_dss_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_rsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_rsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_rsa_camellia_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_rsa_camellia_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.dhe_rsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_ecdsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_ecdsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_ecdsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_ecdsa_null_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_ecdsa_rc4_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_rsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_rsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_rsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_rsa_null_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdh_rsa_rc4_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_null_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_ecdsa_rc4_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_aes_128_gcm_sha256", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_null_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.ecdhe_rsa_rc4_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_1024_rc4_56_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_aes_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_aes_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_camellia_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_camellia_256_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_fips_des_ede3_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_null_md5", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_null_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_rc2_40_md5", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_rc4_128_md5", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_rc4_128_sha", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_rc4_40_md5", true);
user_pref("services.sync.prefs.sync.security.ssl3.rsa_seed_sha", true);
user_pref("services.sync.prefs.sync.security.tls.enable_0rtt_data", true);
user_pref("services.sync.prefs.sync.security.tls.unrestricted_rc4_fallback", true);
user_pref("services.sync.prefs.sync.security.tls.version.fallback-limit", true);
user_pref("services.sync.prefs.sync.security.tls.version.max", true);
user_pref("services.sync.prefs.sync.security.tls.version.min", true);
user_pref("services.sync.prefs.sync.security.xpconnect.plugin.unrestricted", true);
user_pref("services.sync.prefs.sync.services.blocklist.update_enabled", true);
user_pref("services.sync.prefs.sync.shumway.disabled", true);
user_pref("services.sync.prefs.sync.signon.autofillForms", true);
user_pref("services.sync.prefs.sync.signon.autofillForms.http", true);
user_pref("services.sync.prefs.sync.signon.formlessCapture.enabled", true);
user_pref("services.sync.prefs.sync.signon.rememberSignons", true);
user_pref("services.sync.prefs.sync.toolkit.telemetry.archive.enabled", true);
user_pref("services.sync.prefs.sync.toolkit.telemetry.enabled", true);
user_pref("services.sync.prefs.sync.toolkit.telemetry.unified", true);
user_pref("services.sync.prefs.sync.webgl.disable-extensions", true);
user_pref("services.sync.prefs.sync.webgl.disable-fail-if-major-performance-caveat", true);
user_pref("services.sync.prefs.sync.webgl.disabled", true);
user_pref("services.sync.prefs.sync.webgl.enable-debug-renderer-info", true);
user_pref("services.sync.prefs.sync.webgl.min_capability_mode", true);
