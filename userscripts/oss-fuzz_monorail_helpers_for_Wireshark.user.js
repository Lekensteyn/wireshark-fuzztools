// ==UserScript==
// @name        oss-fuzz monorail helpers for Wireshark
// @namespace   https://lekensteyn.nl/
// @include     https://bugs.chromium.org/p/oss-fuzz/issues/*
// @version     1
// @grant       none
// ==/UserScript==

"use strict";
/* jshint browser:true, esversion:6, devel:true */
/* globals URLSearchParams */

var BZ_REST_URL = "https://bugs.wireshark.org/bugzilla/rest.cgi/";
var BZ_BUG_URL = "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=";
var CR_ISSUE_URL = "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=";

var console = {
    log(...args) {
        let msg = args.join(" ");
        window.eval(`console.log(${JSON.stringify(msg)})`);
    }
};

function textMatches(text, comment) {
    function normalize(foo) {
        return foo.trim().replace(/\r\n/g, "\n");
    }
    text = normalize(text);
    comment = normalize(comment);
    return text === comment;
}

function getIssueIdFromUrl(url) {
    if (url && url.indexOf(CR_ISSUE_URL) === 0) {
        var issueId = url.substr(CR_ISSUE_URL.length);
        return +issueId;
    }
    return null;
}

function populateComment(comment) {
    var commentField = document.querySelector("#addCommentTextArea");
    if (!commentField) return;
    if (commentField.value && commentField.value === comment) {
        // same contents, nothing to do.
        return;
    } else {
        // if one comment on the page contains the same content, do nothing.
        var comments = document.querySelector("#ezt-comments");
        var commentList = comments && comments.getAttribute("comment-list");
        commentList = commentList && JSON.parse(commentList);
        var texts = commentList && commentList.map((c) => c.content);
        if (texts && texts.some((c) => c && textMatches(c, comment))) {
            commentField.placeholder = "(up to date)";
            return;
        }
    }

    if (commentField.value) {
        // there is already a value, just add another field for easier copies.
        var newField = document.createElement("button");
        newField.style.display = "block";
        newField.textContent = comment;
        newField.onclick = function (ev) {
            ev.preventDefault();
            commentField.value = comment;
            newField.style.display = "none";
        };
        commentField.parentNode.insertBefore(newField, commentField);
    } else if (comment == "(No upstream bug found)") {
        commentField.placeholder = comment;
    } else {
        commentField.value = comment;
    }
}

function addBugLink(bug) {
    var commentField = document.querySelector("#addCommentTextArea");
    if (!commentField) return;
    var link = document.createElement("a");
    link.style.display = "block";
    link.href = BZ_BUG_URL + bug.id;
    link.textContent = "Bug " + bug.id + " - " + bug.summary;
    link.target = "_blank";
    commentField.parentNode.insertBefore(link, commentField);
    commentField.focus();
}

function fetchBug(url) {
    return fetch(url)
    .then((response) => response.json())
    .then(function(data) {
        if (data.error) {
            console.log("Request failed:", data.message);
            return null;
        }
        if (data.bugs.length === 0) {
            console.log("No bug found for", url);
            return null;
        } else {
            if (data.bugs.length > 1) {
                console.log("WARN: found multiple bugs: " + data.bugs.length);
            }
            return data.bugs[0];
        }
    });
}

function queryBzByIssueId(issueId) {
    var url = BZ_REST_URL + "bug?url=";
    url += encodeURIComponent(CR_ISSUE_URL + issueId);
    return fetchBug(url);
}

function queryBzByBugId(bugId) {
    var url = BZ_REST_URL + "bug/" + bugId;
    return fetchBug(url);
}

// Obtains a list of bugs, recursively fetching the duplicate bug.
function queryBzRecursivelyByBug(bug, results) {
    if (!results) results = [];
    // add discovered bug
    results.push(bug);
    // try to resolve duplicates
    if (bug.dupe_of) {
        return queryBzByBugId(bug.dupe_of).then((bug) => {
            if (bug) {
                return queryBzRecursivelyByBug(bug, results);
            }
            return results;
        });
    }
    // finally return all results if there is no more work.
    return Promise.resolve(results);
}

var COMMENT_TEMPLATE = `
Upstream bug: {upstream URL 1}
(duplicate of {upstream URL 2}, issue 1234)
(duplicate of {upstream URL 3})

Current status: RESOLVED FIXED
`;

if (/\/detail$/.test(location.pathname)) {
    let issueId = new URLSearchParams(location.search).get("id");
    if (issueId) {
        let entries = [];
        queryBzByIssueId(issueId).then(function(bug) {
            if (!bug) {
                return "(No upstream bug found)";
            }
            addBugLink(bug);
            let comment = "Upstream bug: " + BZ_BUG_URL + bug.id + "\n";
            return queryBzRecursivelyByBug(bug).then((bugs) => {
                bugs.shift();
                bugs.forEach((bug) => {
                    comment += "(duplicate of " + BZ_BUG_URL + bug.id;
                    let issueId = getIssueIdFromUrl(bug.url);
                    if (issueId) {
                        comment += ", issue " + issueId;
                    }
                    comment += ")\n";
                    // Add link for the duplicate
                    addBugLink(bug);
                });
                if (bugs.length) {
                    bug = bugs[bugs.length - 1];
                }
                comment += "\nCurrent status: ";
                if (bug.resolution) {
                    comment += bug.status + " " + bug.resolution;
                } else {
                    comment += bug.status + " (unfixed)";
                }
                return comment;
            });
        }).then((comment) => {
            populateComment(comment);
        }).catch(function(error) {
            console.log(error);
        });
    }
}
