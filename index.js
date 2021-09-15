const express = require("express"),
	{
		verify: verify
	} = require("hcaptcha"),
	secret = process.argv[3],
	fs = require("fs"),
	http = require("http"),
	bodyParser = require("body-parser"),
	crypto = require("crypto"),
	cookieParser = require("cookie-parser"),
	UglifyJS = require("uglify-js"),
	CleanCSS = require("clean-css"),
	irc = require("irc");
var app = express();
app.use(express.urlencoded({
	extended: false
})), app.use(express.json()), app.use(cookieParser());
var server = app.listen(4006, "0.0.0.0", function () {
	LOG("Server listening on http://" + server.address().address + ":" + server.address().port)
});
setTimeout(function () {
	app.use(function (e, s, t) {
		return s.status(404).end(statusMsg("404 Not Found"))
	}), app.use(function (e, s, t, n) {
		return ERR(e), t.status(500).send(statusMsg("500 Internal Server Error"))
	})
}, 100);

{ // Utility Functions
	function LOG(e) {
		const s = new Date,
			t = s.getHours() + ":" + s.getMinutes() + ":" + s.getSeconds() + " [info]\t";
		console.log(t + e + "\x1b[0m")
	}

	function WARN(e) {
		const s = new Date,
			t = s.getHours() + ":" + s.getMinutes() + ":" + s.getSeconds() + " [WARN]\x1b[1m\x1b[33m\t";
		console.warn(t + e + "\x1b[0m")
	}

	function ERR(e) {
		const s = new Date,
			t = s.getHours() + ":" + s.getMinutes() + ":" + s.getSeconds() + " [ERR]\x1b[1m\x1b[31m\t";
		console.error(t + e + "\x1b[0m")
	}

	function stringToBase64(e) {
		return Buffer.from(e).toString("base64")
	}

	function base64ToString(e) {
		return Buffer.from(e, "base64").toString()
	}

	function safeString(e) {
		return e.replace(/</g, "≤").replace(/>/g, "≥").replace(/\\/g, "/").replace(/"/g, "“")
	}

	function checkIP(e, s) {
		if ("127.0.0.1" == e || e.startsWith("192.")) return {
			status: "success",
			country: "localhost",
			proxy: "false"
		};
		const t = {
			hostname: "ip-api.com",
			port: 80,
			path: `/json/${e}?fields=status,message,country,proxy`,
			method: "GET"
		},
			n = http.request(t, t => {
				console.log(`statusCode: ${t.statusCode}`);
				var n = "";
				t.on("data", e => {
					n += e
				}), t.on("end", function () {
					s(JSON.parse(n.toString()))
				}), t.on("error", function (t) {
					ERR(`Failed to check IP ${e}: ${t}`), s(null)
				})
			});
		n.on("error", e => {
			console.error(e)
		}), n.end()
	}

	function redirectTo(e) {
		return `<!DOCTYPE HTML><head><title>Fede's Chat</title></head><body><meta http-equiv="Refresh" content="0; url='${e}'" /></body>`
	}

	function statusMsg(e) {
		return fs.readFileSync("./public/msg.html").toString().replace("%t", e)
	}

	function isTokenValid(e) {
		if (!e || !e.split("&")[1]) return !1;
		const s = base64ToString(e.split("&")[0]),
			t = e.split("&")[1];
		return !(!tokens[s] || !logins[s].pass) && tokens[s].toString() == t.toString()
	}

	function timeDiff(e) {
		var s = parseInt(Date.now() / 1e3) - e;
		return s = s > 86400 ? `${Math.round(s / 86400)} days ago` : s > 7200 ? `${Math.round(s / 3600)}h ago` : s > 120 ? `${Math.round(s / 60)}min ago` : "Now"
	}

	function isEven(e) {
		return e % 2 == 0
	}
	function parseText(e) {
		for (i in pText = e.split("::"), pText) isEven(i) || (pText[i] = `<img class="emoji" style="width:32px; height: 32px;" src="/assets/emoji/${pText[i]}.webp"></img>`);
		return pText.join("")
	}
}
{ // Passwords handling
	const e = fs.readFileSync("./commonPasswords.txt").toString().split(",");
	var logins = {},

		loginsChanged = !0,
		tokens = {},
		bannedIPs = ["51.158.191.33"];

	function loadPass() {
		fs.readFile("./save/logins.json", function (e, s) {
			if (e) return ERR(e);
			logins = JSON.parse(s.toString()), LOG("Loaded logins.")
		})
	}

	function savePass() {
		fs.writeFile("./save/logins.json", JSON.stringify(logins).replace(/},/g, "},\n"), function (e) {
			if (e) return ERR(e)
		})
	}
	loadPass(), setInterval(function () {
		loginsChanged && (savePass(), loginsChanged = !1)
	}, 1e4), app.post("/register", function (s, t) {
		const n = s.body["h-captcha-response"],
			r = s.socket.remoteAddress,
			o = s.body.username;
		bannedIPs.includes(r) ? setTimeout(function () {
			return t.status(401).end(redirectTo("login.html?401"))
		}, 500) : n ? verify(secret, n, r).then(n => {
			if (!0 === n.success) {
				if (!o || !s.body.password) return t.status(400).send("Missing username/password");
				if (o.lenght > 32) t.status(400).end(redirectTo("register.html?longU"));
				else if (s.body.password.lenght > 128) t.status(400).end(redirectTo("register.html?longP"));
				else {
					if (!1 == !logins[o]) return t.status(400).end(redirectTo("register.html?alr"));
					if (o.includes(":") || o.includes("<") || o.includes(">")) return t.status(400).end("Username can't contain the characters: : < >");
					["system", "server", "admin", "owner", "moderator", "mod", "fede"].includes(o.toLowerCase()) || o.toLowerCase.startsWith("irc") ? t.status(400).end(redirectTo("register.html?inv")) : (s.body.password.length < 5 || e.includes(s.body.password.toLowerCase())) && t.status(400).end(redirectTo("register.html?c"))
				}
				const n = crypto.randomBytes(16).toString("base64"),
					i = crypto.createHmac("sha256", n).update(s.body.password).digest("base64");
				logins[o] = {
					salt: n,
					pass: i,
					ip: r,
					token: crypto.randomBytes(48).toString("base64"),
					recover: crypto.randomBytes(32).toString("base64")
				}, t.cookie("token", stringToBase64(o) + "&" + tokens[o]), t.status(200).send(statusMsg(`<h1>Welcome ${o}!</h1><p>You registered successfully!<br>Your recovery key is:<br><tt>${logins[o].recover}</tt><br>\n                    <b>Store it somewhere safe, if you lose it you will be unable to recover your account or to change password!</b>`)), LOG(`User ${o} with IP ${r} registered.`), loginsChanged = !0
			} else t.status(400).end(redirectTo("login.html?captcha"))
		}).catch(ERR) : t.status(400).end(redirectTo("login.html?captcha"))
	}), app.post("/login", function (e, s) {
		const t = e.body["h-captcha-response"],
			n = e.socket.remoteAddress,
			r = e.body.username;
		bannedIPs.includes(n) ? setTimeout(function () {
			return s.status(401).end("401 Unauthorized")
		}, 500) : t ? verify(secret, t, n).then(t => {
			if (!0 === t.success) {
				if (!r || !e.body.password) return s.status(400).send("Missing username/password");
				if (r.lenght > 32) return s.status(400).end(redirectTo("login.html?longU"));
				if (e.body.password.lenght > 128) return s.status(400).end(redirectTo("login.html?longP"));
				if (!logins[r]) return s.status(400).end(redirectTo("login.html?wrongPw"));
				const t = logins[r].salt,
					i = crypto.createHmac("sha256", t).update(e.body.password).digest("base64");
				logins[r].pass != i && s.status(200).send(wrongPassMsg);
				var o = crypto.randomBytes(256).toString("base64");
				tokens[r] = o, s.cookie("token", stringToBase64(r) + "&" + o), s.status(200).send('\n                <meta http-equiv="refresh" content="0; URL=/app" />'), LOG(`User ${r} logged in with IP ${n}`), loginsChanged = !0, checkIP(n, function (e) {
					e && ("fail" == e.status && WARN(`API failed to check IP ${n}: ${e.message}`), LOG(`User's country is ${e.country}. Is using VPN: ${e.proxy}`))
				})
			} else s.status(400).end(redirectTo("login.html?captcha"))
		}).catch(ERR) : s.status(400).end(redirectTo("login.html?captcha"))
	})
}
{ // Extra Login GET
	app.get("/r", function (e, s) {
		return e.cookies && isTokenValid(e.cookies.token) ? s.status(200).end(redirectTo("/app")) : s.status(200).end(redirectTo("/register.html"))
	}), app.get("/l", function (e, s) {
		return e.cookies && isTokenValid(e.cookies.token) ? s.status(200).end(redirectTo("/app")) : s.status(200).end(redirectTo("/login.html"))
	});
}
{ // Messages handling
	var messages = [],
		lastMsg = 0,
		userList = {
			Fede: {
				last: "1000"
			}
		};

	function checkMsgLength() {
		messages.length > 200 && messages.shift()
	}
	messages.push(["System", Math.round(Date.now() / 1e3), "Server started."]), app.get("/app", function (e, s) {
		if (!e.cookies || !isTokenValid(e.cookies.token)) return s.status(401).end(redirectTo("/login.html"));
		const t = base64ToString(e.cookies.token.split("&")[0]);
		s.status(200).end(fs.readFileSync("./public/app.html").toString().replace(/%nm/g, t))
	}), app.post("/chat", function (e, s) {
		const t = e.cookies;
		if (!t || !isTokenValid(t.token)) return s.status(401).end("<p>401 Unauthorized.</p>");
		const n = base64ToString(t.token.split("&")[0]);
		var r = "<div>";
		for (i in messages) messages[i][0] != n ? r += `<div class="container"><div class="containerImg">${messages[i][0]}</div><p>${messages[i][2]}</p><span class="time-right">${timeDiff(messages[i][1])}</span></div>` : r += `<div class="container darker"><div class="containerImg">${messages[i][0]}</div><p>${messages[i][2]}</p><span class="time-right">${timeDiff(messages[i][1])}</span></div>`;
		r += "</div>", s.status(200).end(r)
	}), app.post("/rec", function (e, s) {
		if (Date.now() < lastMsg + 5e3) return s.status(200).end("<p>true</p>");
		if (!e.cookies || !isTokenValid(e.cookies.token)) return s.status(401).end("<p>401</p>");
		s.status(200).end("<p>false</p>");
		const t = base64ToString(e.cookies.token.split("&")[0]);
		userList[t] = {
			last: Math.round(Date.now() / 1e3)
		}
	}), app.post("/list", function (e, s) {
		const t = e.cookies;
		if (!t || !isTokenValid(t.token)) return s.status(401).end("<p>401 Unauthorized.</p>");
		const n = base64ToString(t.token.split("&")[0]);
		var r = "<div>";
		for (i in userList) userList[i] && userList[i].last && parseInt(userList[i].last) + 15 >= Math.round(Date.now() / 1e3) && (i == n ? r += `<div title="You">${i}</div>` : r += `<div style="color:#cccccc">${i}</div>`);
		r += "</div>", s.status(200).end(r)
	}), app.post("/sendMessage", function (e, s) {
		const t = e.cookies,
			n = e.body;
		if (!t || !isTokenValid(t.token)) return s.status(401).end("<p>401 Unauthorized.</p>");
		const r = base64ToString(t.token.split("&")[0]);
		if (!n.message || n.message.toString().length < 1) return s.status(400).end("Missing message.");
		var o = safeString(n.message.toString());
		if (o.length > 512) return s.status(400).end("<p>Message is too long.</p>");
		fs.appendFile("./save/msglog.txt", `${r} ${o}\n`, function (e) {
			if (e) throw new ERR(e)
		}), "Fede" == r && (o = parseText(o)), messages.push([r, Math.round(Date.now() / 1e3), o]), s.status(200).end("<p>ok</p>"), lastMsg = Date.now(), checkMsgLength(), sendIrcMessage(r, o)
	})
}
{ // IRC
	var ircClient = new irc.Client("irc.oftc.net", "WowneroChat", {
		channels: ["#wownero"],
		debug: !1
	});

	function sendIrcMessage(e, s) {
		ircClient.say("#wownero", e + ": " + s)
	}
	ircClient.addListener("message", function (e, s, t) {
		messages.push([`<b>IRC</b>: ${e}`, Math.round(Date.now() / 1e3), safeString(t)]), fs.appendFile("./save/msglog.txt", `IRC ${e} ${t}\n`, function (e) {
			if (e) throw new ERR(e)
		}), lastMsg = Date.now()
	}), ircClient.addListener("error", function (e) {
		console.error(e)
	}), ircClient.addListener("join", function (e, s, t) {
		ircClient.say("NickServ", "IDENTIFY " + process.argv[2])
	})
}
{ // Static content and cache
	var cache = {};
	app.get("*", function (e, s) {
		var t = e.url.split("?")[0];
		if ("/" === t && (t = "/index.html"), cache[t]) return s.status(200).end(cache[t]);
		fs.readFile("./public" + t, function (e, n) {
			if (e) return e.toString().includes("ENOENT") ? s.status(404).end(statusMsg("404 Not Found")) : (ERR(`URL ${t} ${e}`), s.status(500).end(statusMsg("500 Internal Server Error<br>We've seen the issue, and we're working to fix it!")));
			if (s.status(200).end(n), n.length / 1e3 < 70) {
				if (t.endsWith(".js")) {
					n = n.toString();
					var r = UglifyJS.minify(n);
					r.error ? ERR(r.error) : (n = r.code, cache[t] = n)
				} else t.endsWith(".css") && (n = n.toString(), new CleanCSS({}).minify(n, function (e, s) {
					if (e) return ERR(e);
					n = s.styles, cache[t] = n
				}));
				cache[t] = n
			}
		})
	});
}