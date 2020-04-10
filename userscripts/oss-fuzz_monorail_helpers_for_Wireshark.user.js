// ==UserScript==
// @name        oss-fuzz monorail helpers for Wireshark
// @namespace   https://lekensteyn.nl/
// @include     https://bugs.chromium.org/p/oss-fuzz/issues/*
// @version     1
// @grant       none
// ==/UserScript==

"use strict";
/* jshint browser:true, esversion:6, devel:true */
/* globals URLSearchParams, KeyboardEvent */

var BZ_REST_URL = "https://bugs.wireshark.org/bugzilla/rest.cgi/";
var BZ_BUG_URL = "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=";
var CR_ISSUE_URL = "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=";

function getIssueIdFromUrl(url) {
    if (url && url.indexOf(CR_ISSUE_URL) === 0) {
        var issueId = url.substr(CR_ISSUE_URL.length);
        return +issueId;
    }
    return null;
}

function getShadowRoot(path, elementSelector) {
    let leaf = path.split(' ').reduce((node, selector) => node?.querySelector(selector).shadowRoot, document);
    return elementSelector ? leaf?.querySelector(elementSelector) : leaf;
}

function getCommentField() {
    let path = 'mr-app mr-issue-page mr-issue-details.main-item mr-edit-issue mr-edit-metadata';
    let commentField = getShadowRoot(path, '#commentText');
    if (!commentField) {
        console.log('Comment box not found');
    }
    return commentField;
}

function populateComment(comment, needle) {
    var commentField = getCommentField();
    if (!commentField) return;
    if (commentField.value && commentField.value === comment) {
        // same contents, nothing to do.
        return;
    } else {
        // if one comment on the page contains the same content, do nothing.
        var commentsList = getShadowRoot('mr-app mr-issue-page mr-issue-details.main-item mr-comment-list');
        // Note that the textContent does not reflect the true visible comment,
        // newlines (from <br>) are gone and the contents of the style tag are
        // present. There is also an internal '__content' property on the
        // mr-comment-content element, but we cannot seem to check it here.
        var texts = Array.from(commentsList.querySelectorAll('mr-comment'),
            (c) => c.shadowRoot.querySelector('mr-comment-content'))
            .map((c) => c.shadowRoot.textContent);
        if (texts && texts.some((c) => c && c.includes(needle))) {
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
        // ensure that the "Save changes" button is enabled.
        commentField.dispatchEvent(new KeyboardEvent('keyup'));
    }
}

function addBugLink(bug) {
    var commentField = getCommentField();
    if (!commentField) return;
    var link = document.createElement("a");
    link.style.display = "block";
    link.href = BZ_BUG_URL + bug.id;
    link.textContent = "Bug " + bug.id + " - " + bug.summary;
    link.target = "_blank";
    link.title = `${bug.status} ${(bug.resolution||'(unfixed)')}\nCreated ${bug.creation_time}\nUpdated ${bug.last_change_time}`;
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
            let bug_url = BZ_BUG_URL + bug.id;
            let comment = `Upstream bug: ${bug_url}\n`;
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
                return [comment, bug_url];
            });
        }).then(([comment, needle]) => {
            populateComment(comment, needle);
        }).catch(function(error) {
            console.log(error);
        });
    }
}
