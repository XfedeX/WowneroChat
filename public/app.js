var curUserHold = "";

function listClicked() {
    "" != curUserHold && (document.getElementById("messageInput").value = curUserHold)
}

function safeString(e) {
    return e.replace(/</g, "≤").replace(/>/g, "≥").replace(/\\/g, "/").replace(/"/g, "“")
}

function sendMessage() {
    var e = document.getElementById("messageInput");
    "" != e.value && (document.getElementById("chat").innerHTML += `<div class="container darker"><div class="containerImg loadDiv">You</div><p>${safeString(e.value)}</p><span class="time-right">Sending...</span></div>`, 1 == isBtm && (chat.scrollTop = chat.scrollHeight), postReq(function(e, t) {
        429 == e && alert("You're sending messages too fast! Please calm down.")
    }, "/sendMessage", `{"message" :"${safeString(e.value)}"}`), e.value = "", refresh())
}

function postReq(e, t, n = "{}") {
    try {
        var s = new XMLHttpRequest;
        s.open("POST", t), s.setRequestHeader("Content-Type", "application/json"), s.onreadystatechange = function() {
            4 == this.readyState && e(s.status, s.response)
        }, s.onerror = function() {
            e(1, "Connection Error")
        }, s.send(n)
    } catch (t) {
        e(1, "Connection Error")
    }
}
document.getElementById("userList").addEventListener("mouseover", function(e) {
    const t = e.target.innerHTML;
    t.startsWith("<") || (curUserHold = t.toString())
}, !1);
var isBtm = !1;

function newMessages() {
    postReq(function(e, t) {
        if (401 == e) return window.location.replace("/login.html");
        200 == e && t.includes("true") && refresh()
    }, "/rec")
}

function refreshList() {
    postReq(function(e, t) {
        if (401 == e) return window.location.replace("/login.html");
        200 == e && (document.getElementById("userList").innerHTML = t)
    }, "/list")
}
setInterval(function() {
    const e = document.getElementById("chat");
    if (e.innerHTML.length != oldLength) {
        if (e.scrollHeight - e.scrollTop > 500) return;
        oldLength = e.innerHTML.length
    }
    isBtm = e.scrollHeight - Math.abs(e.scrollTop) <= 1.2 * e.clientHeight ? 1 : 0
}, 1e3);
var oldLength = 0;

function refresh() {
    document.hasFocus && postReq(function(e, t) {
        if (401 == e) return window.location.replace("/login.html");
        if (200 != e) return;
        const n = document.getElementById("chat");
        n.innerHTML = t, console.log(isBtm), 1 === isBtm && (n.scrollTop = n.scrollHeight)
    }, "/chat")
}
refresh(), refreshList(), setInterval(function() {
    newMessages()
}, 2e3), setInterval(function() {
    refreshList()
}, 6e3);