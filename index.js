const express = require("express");
const { verify } = require("hcaptcha");
const secret = process.argv[3];
const fs = require("fs")
const http = require("http");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const UglifyJS = require("uglify-js");
const CleanCSS = require("clean-css");
const irc = require("irc")

// Start up server

var app = express();

app.use(express.urlencoded({
    extended: true
}))
app.use(express.json())
app.use(cookieParser())

var server = app.listen(4006, "0.0.0.0", function () {
    var host = server.address().address
    var port = server.address().port

    LOG("Server listening on http://" + host + ":" + port)
})



// Error handling.
{
    setTimeout(function () {
        //app.use(express.static("public"))

        app.use(function (req, res, next) {
            // Do logging and user-friendly error message display.
            //console.log('Route does not exist')
            //next(new Error('Not Found'))
            return res.status(404).end(statusMsg("404 Not Found"))
        })

        app.use(function (err, req, res, next) {
            // Do logging and user-friendly error message display
            ERR(err)
            return res.status(500).send(statusMsg("500 Internal Server Error"))
        })
    }, 100)
}

// Utility functions
{
    function LOG(text) {
        const date_ob = new Date();
        const time = date_ob.getHours() + ":" + date_ob.getMinutes() + ":" + date_ob.getSeconds() + " [info]\t"
        console.log(time + text + "\x1b[0m")
    }
    function WARN(text) {
        const date_ob = new Date();
        const time = date_ob.getHours() + ":" + date_ob.getMinutes() + ":" + date_ob.getSeconds() + " [WARN]\x1b[1m\x1b[33m\t"
        console.warn(time + text + "\x1b[0m")
    }
    function ERR(text) {
        const date_ob = new Date();
        const time = date_ob.getHours() + ":" + date_ob.getMinutes() + ":" + date_ob.getSeconds() + " [ERR]\x1b[1m\x1b[31m\t"
        console.error(time + text + "\x1b[0m")
    }

    function stringToBase64(str) {
        return Buffer.from(str).toString("base64")
    }
    function base64ToString(str) {
        return Buffer.from(str, "base64").toString()
    }
    function safeString(str) {
        return str.replace(/</g, "≤").replace(/>/g, "≥").replace(/\\/g, "/").replace(/"/g, "“")
    }

    function checkIP(ipToCheck, callbackFunc) {
        if (ipToCheck == "127.0.0.1" || ipToCheck.startsWith("192.")) {
            return {
                "status": "success",
                "country": "localhost",
                "proxy": "false"
            }
        }
        const options = {
            hostname: "ip-api.com",
            port: 80,
            path: `/json/${ipToCheck}?fields=status,message,country,proxy`,
            method: "GET"
        }

        const req = http.request(options, res => {
            console.log(`statusCode: ${res.statusCode}`)
            var data = "";
            res.on("data", d => {
                data += d;
            })
            res.on("end", function () {
                callbackFunc(JSON.parse(data.toString()))
            })
            res.on("error", function (err) {
                ERR(`Failed to check IP ${ipToCheck}: ${err}`)
                callbackFunc(null)
            })
        })

        req.on('error', error => {
            console.error(error)
        })

        req.end()
    }


    function redirectTo(url) {
        return `<!DOCTYPE HTML><head></head><body><meta http-equiv="Refresh" content="0; url='${url}'" /></body>`
    }

    function statusMsg(text) {
        return fs.readFileSync("./public/msg.html").toString().replace("%t", text)
    }
    function isTokenValid(rawToken) {
        if (!rawToken || !rawToken.split("&")[1]) {
            return false
        }

        const name = base64ToString(rawToken.split("&")[0])
        const token = rawToken.split("&")[1]

        if (!tokens[name] || !logins[name].pass) {
            return false
        }
        if (tokens[name].toString() != token.toString()) {
            return false
        }
        return true
    }

    function timeDiff(oldTime) {
        const newTime = parseInt(Date.now() / 1000)
        var a = newTime - oldTime
        if (a > 86400) {
            a = `${Math.round(a / 86400)} days ago`
        } else if (a > 7200) {
            a = `${Math.round(a / 3600)}h ago`
        } else if (a > 60) {
            a = `${Math.round(a / 60)}min ago`
        } else {
            a = "Now"
        }
        return a
    }

    function isEven(number) {
        return (number % 2) == 0
    }

}


// Login handling
{

    const commonPasswords = fs.readFileSync("./commonPasswords.txt").toString().split(",")

    var logins = {

    }
    var loginsChanged = true;


    var tokens = {}
    var bannedIPs = ["51.158.191.33"]


    // Variables saving and loading

    function loadPass() {
        fs.readFile("./save/logins.json", function (err, data) {
            if (err) {
                return ERR(err)
            }
            logins = JSON.parse(data.toString())
            LOG("Loaded logins.")
        })
    }

    function savePass() {

        fs.writeFile("./save/logins.json", JSON.stringify(logins).replace(/},/g, "},\n"), function (err) {
            if (err) {
                return ERR(err)
            }
        })
    }

    loadPass()
    setInterval(function () {
        if (loginsChanged) {
            savePass()
            loginsChanged = false;
        }
    }, 10000)

    // Login

    app.post('/register', function (req, res) {
        const curToken = req.body["h-captcha-response"];
        const ip = req.socket.remoteAddress
        const username = req.body.username

        if (bannedIPs.includes(ip)) {
            setTimeout(function () {
                return res.status(401).end(redirectTo("login.html?401"))
            }, 500)
            return;
        }

        if (!curToken) {
            //return next(err);
            res.status(400).end(redirectTo("login.html?captcha"))
            return
        }
        verify(secret, curToken, ip)
            .then((data) => {
                if (data.success === true) {

                    if (!username || !req.body.password) {
                        return res.status(400).send("Missing username/password");
                    }

                    if (username.lenght > 32) {
                        res.status(400).end(redirectTo("register.html?longU"))
                    } else if (req.body.password.lenght > 128) {
                        res.status(400).end(redirectTo("register.html?longP"))
                    } else if ((!logins[username]) === false) {
                        return res.status(400).end(redirectTo("register.html?alr"))
                    } else if (username.includes(":") || username.includes("<") || username.includes(">")) {
                        return res.status(400).end("Username can't contain the characters: : < >")
                    } else if (["system", "server", "admin", "owner", "moderator", "mod", "fede"].includes(username.toLowerCase()) || username.toLowerCase.startsWith("irc")) {
                        res.status(400).end(redirectTo("register.html?inv"))
                    } else if (req.body.password.length < 5 || commonPasswords.includes(req.body.password.toLowerCase())) {
                        res.status(400).end(redirectTo("register.html?c"))
                    }

                    const salt = crypto.randomBytes(16).toString('base64');
                    const hashedPw = crypto.createHmac("sha256", salt).update(req.body.password).digest("base64")

                    logins[username] = {
                        salt: salt,
                        pass: hashedPw,
                        ip: ip,
                        token: crypto.randomBytes(48).toString("base64"),
                        recover: crypto.randomBytes(32).toString("base64")
                    }

                    res.cookie("token", stringToBase64(username) + "&" + tokens[username])
                    res.status(200).send(
                        statusMsg(`<h1>Welcome ${username}!</h1><p>You registered successfully!<br>Your recovery key is:<br><tt>${logins[username].recover}</tt><br>
                    <b>Store it somewhere safe, if you lose it you will be unable to recover your account or to change password!</b>`))

                    LOG(`User ${username} with IP ${ip} registered.`)

                    loginsChanged = true;
                } else {
                    res.status(400).end(redirectTo("login.html?captcha"))
                }
            }).catch(ERR);



    });


    app.post('/login', function (req, res) {
        const curToken = req.body["h-captcha-response"];
        const ip = req.socket.remoteAddress
        const username = req.body.username

        if (bannedIPs.includes(ip)) {
            setTimeout(function () {
                return res.status(401).end("401 Unauthorized")
            }, 500)
            return;
        }

        if (!curToken) {
            //return next(err);
            res.status(400).end(redirectTo("login.html?captcha"))
            return
        }

        verify(secret, curToken, ip)
            .then((data) => {
                if (data.success === true) {

                    if (!username || !req.body.password) {
                        return res.status(400).send("Missing username/password");
                    }
                    if (username.lenght > 32) {
                        return res.status(400).end(redirectTo("login.html?longU"))
                    } else if (req.body.password.lenght > 128) {
                        return res.status(400).end(redirectTo("login.html?longP"))
                    }
                    if (!logins[username]) {
                        return res.status(400).end(redirectTo("login.html?wrongPw"))
                    }

                    const salt = logins[username].salt;
                    const hashedPw = crypto.createHmac("sha256", salt).update(req.body.password).digest("base64")

                    if (logins[username].pass != hashedPw) {
                        res.status(200).send(wrongPassMsg)
                    }

                    var random = crypto.randomBytes(256).toString('base64')

                    tokens[username] = random;

                    res.cookie("token", stringToBase64(username) + "&" + random)

                    res.status(200).send(`
                <meta http-equiv="refresh" content="0; URL=/app" />`)
                    LOG(`User ${username} logged in with IP ${ip}`)
                    loginsChanged = true;

                    checkIP(ip, function (data) {
                        if (!data) return;

                        if (data["status"] == "fail") {
                            WARN(`API failed to check IP ${ip}: ${data.message}`)
                        }
                        LOG(`User's country is ${data.country}. Is using VPN: ${data["proxy"]}`)
                    })
                } else {
                    res.status(400).end(redirectTo("login.html?captcha"))
                }
            }).catch(ERR);

    });
}
// Extra login GET
{
    app.get("/r", function (req, res) {
        if (!req.cookies || !isTokenValid(req.cookies.token)) {
            return res.status(200).end(redirectTo("/register.html"))
        }
        return res.status(200).end(redirectTo("/app"))
    })
    app.get("/l", function (req, res) {
        if (!req.cookies || !isTokenValid(req.cookies.token)) {
            return res.status(200).end(redirectTo("/login.html"))
        }
        return res.status(200).end(redirectTo("/app"))
    })
}

// Chat
{
    var messages = []
    var lastMsg = 0

    var userList = {
        "Fede": { "last": "1000" }
    }

    messages.push(["System", Math.round(Date.now() / 1000), "Server started."])
    app.get("/app", function (req, res) {
        if (!req.cookies || !isTokenValid(req.cookies.token)) {
            return res.status(401).end(redirectTo("/login.html"))
        }
        const name = base64ToString((req.cookies.token).split("&")[0])
        res.status(200).end(fs.readFileSync("./public/app.html").toString().replace(/%nm/g, name))
    })

    app.post("/chat", function (req, res) {
        const body = (req.cookies)
        if (!body || !isTokenValid(body.token)) {
            return res.status(401).end("<p>401 Unauthorized.</p>")
        }
        const name = base64ToString((body.token).split("&")[0])


        var msgList = `<div>`
        for (i in messages) {
            if (messages[i][0] != name) {
                msgList += `<div class="container"><div class="containerImg">${messages[i][0]}</div><p>${messages[i][2]}</p><span class="time-right">${timeDiff(messages[i][1])}</span></div>`
            } else {
                msgList += `<div class="container darker"><div class="containerImg">${messages[i][0]}</div><p>${messages[i][2]}</p><span class="time-right">${timeDiff(messages[i][1])}</span></div>`
            }
        }
        msgList = msgList + "</div>"

        res.status(200).end(msgList)
    })

    app.post("/rec", function (req, res) {
        if (Date.now() < lastMsg + 5000) {
            return res.status(200).end("<p>true</p>")
        }
        if (!req.cookies || !isTokenValid(req.cookies.token)) {
            return res.status(401).end("<p>401</p>")
        }
        res.status(200).end("<p>false</p>")
        const name = base64ToString((req.cookies.token).split("&")[0])

        //userList[name].last = Math.round(Date.now() / 1000)

        userList[name] = { "last": Math.round(Date.now() / 1000) }

    })

    app.post("/list", function (req, res) {
        const body = req.cookies
        if (!body || !isTokenValid(body.token)) {
            return res.status(401).end("<p>401 Unauthorized.</p>")
        }
        const name = base64ToString((body.token).split("&")[0])

        var text = "<div>"
        for (i in userList) {

            if (!userList[i] || !userList[i].last) {

            } else if (parseInt(userList[i].last) + 15 >= Math.round(Date.now() / 1000)) {
                if (i == name) {
                    text += `<div title="You">${i}</div>`
                } else {
                    text += `<div style="color:#cccccc">${i}</div>`
                }
            }
        }
        text += "</div>"
        //LOG(JSON.stringify(userList).replace(/,/g, ",\n"))
        res.status(200).end(text)

    })

    app.post("/sendMessage", function (req, res) {
        const cookies = (req.cookies);
        const body = req.body;
        if (!cookies || !isTokenValid(cookies.token)) {
            return res.status(401).end("<p>401 Unauthorized.</p>")
        }
        const username = base64ToString((cookies.token).split("&")[0])

        if (!body.message || body.message.toString().length < 1) {
            return res.status(400).end("Missing message.")
        }
        var message = safeString(body.message.toString())
        if (message.length > 512) {
            return res.status(400).end("<p>Message is too long.</p>")
        }
        fs.appendFile("./save/msglog.txt", `${username} ${message}\n`, function (err) {
            if (err) {
                throw new ERR(err)
            }
        })
        if (username == "Fede") {
            message = parseText(message)
        }
        messages.push([username, Math.round(Date.now() / 1000), message])
        res.status(200).end("<p>ok</p>")

        lastMsg = Date.now()
        checkMsgLength()

        sendIrcMessage(username, message)
    })

    function checkMsgLength() {
        if (messages.length > 200) {
            messages.shift()
        }
    }
}

// Images Parsing
{
    function parseText(text) {
        pText = text.split(`::`)
        for (i in pText) {

            if (!isEven(i)) {
                pText[i] = `<img class="emoji" style="width:32px; height: 32px;" src="/assets/emoji/${pText[i]}.webp"></img>`
            }
        }
        return pText.join("")
    }
}

// IRC Bridge
{

    var ircClient = new irc.Client("irc.oftc.net", "WowneroChat", {
        channels: ["#wownero"],
        debug: false,
    });
    
    ircClient.addListener("message", function (from, to, message) {

        messages.push([`<b>IRC</b>: ${from}`, Math.round(Date.now() / 1000), safeString(message)])

        fs.appendFile("./save/msglog.txt", `IRC ${from} ${message}\n`, function (err) {
            if (err) {
                throw new ERR(err)
            }
        })
        lastMsg = Date.now()

    });

    ircClient.addListener('error', function (message) {
        console.error(message)
    });

    ircClient.addListener("join", function (channel, nick, message) {
        //console.log(channel + " User " + nick + " joined: " + message)
        ircClient.say('NickServ', "IDENTIFY " + process.argv[2]);

    });
/*
    ircClient.addListener("ping", function (server) {
        console.log("Ping! " + server)
    })

    ircClient.addListener("registered", function (message) {
        console.log("Registered! " + message)
    })

    ircClient.addListener("quit", function (nick, reason, channels, message) {
        console.log(`${nick} quit because ${reason} channels ${channels} message ${message}`)
    })
*/
    function sendIrcMessage(user, message) {
        ircClient.say("#wownero", user + ": " + message)
    }

}

// Static content
{
    var cache = {}
    app.get("*", function (req, res) {
        var url = req.url.split("?")[0]
        if (url === "/") {
            url = "/index.html"
        }
        if (cache[url]) {
            return res.status(200).end(cache[url])
        }
        fs.readFile("./public" + url, function (err, data) {
            if (err) {
                if (err.toString().includes("ENOENT")) {
                    return res.status(404).end(statusMsg("404 Not Found"))
                } else {
                    ERR(`URL ${url} ${err}`)
                    return res.status(500).end(statusMsg("500 Internal Server Error<br>We've seen the issue, and we're working to fix it!"))
                }
            }
            res.status(200).end(data)
            var size = data.length / 1000;

            if (size < 70) { // To save RAM, only cache files smaller than 70KB

                if (url.endsWith(".js")) {
                    data = data.toString()
                    var result = UglifyJS.minify(data);
                    if (result.error) {
                        ERR(result.error)
                    } else {
                        data = result.code;
                        cache[url] = data

                    }
                } else if (url.endsWith(".css")) {
                    data = data.toString()
                    new CleanCSS({}).minify(data, function (error, output) {
                        if (error) {
                            return ERR(error)
                        } else {
                            data = output["styles"]
                            cache[url] = data

                        }
                    });

                }

                cache[url] = data

            }
        })
    })
}
