// ==UserScript==
// @name        Wireshark oss-fuzz bugzilla
// @namespace   https://lekensteyn.nl/
// @description Improve oss-fuzz bugs handling
// @include     https://bugs.wireshark.org/bugzilla/buglist.cgi?*oss-fuzz*
// @version     1
// @grant       none
// ==/UserScript==

Array.from(document.querySelectorAll(
    ".bz_bug_file_loc_column a[href^='https://bugs.chromium.org/p/oss-fuzz/']"
))
    .map((a) => {
        var bugid = a.href.match(/.*\/detail\?id=(\d+)$/);
        if (bugid) {
            a.textContent = bugid[1];
        }
});
