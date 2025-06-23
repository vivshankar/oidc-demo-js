const PORT = process.env.PORT || 3000;

// initialize libraries
const express = require('express');
const https = require("https");
const fs = require("fs");
const path = require("path");
const session = require('express-session');
const handlebars = require('express-handlebars');
const sessionRoutes = require('./routes/session-route');
const usersRoutes = require('./routes/users-route');

// initialize handlebars
var hbs = handlebars.create({
    helpers: {
        formatPurpose: function(purposeName, version) {
            if (purposeName == 'ibm-oauth-scope') {
                return 'OAuth Scope';
            }

            return `${purposeName} (Version ${version})`
        },
        formatDate: function (badDate) {
            var dMod = new Date(badDate * 1000);
            return dMod.toLocaleDateString();
        },
        formatState: function (state) {
            var stateOpt = {
                1: "Consent allow",
                2: "Consent deny",
                3: "Opt-in",
                4: "Opt-out",
                5: "Transparent"
            }
            return stateOpt[state];
        },
        formatAccessType: function (accessType) {
            if (accessType == "default") {
                return "";
            }
            return accessType;
        },
        formatAttribute: function (attribute) {
            if (attribute == "") {
                return "–";
            }
            else {
                return attribute;
            }
        }
    },
    layoutsDir: __dirname + '/../views/layouts',
    partialsDir: __dirname + '/../views/partials',
    extname: 'hbs',
    defaultLayout: 'default',
});

// initialize the app
const app = express();
app.set('view engine', 'hbs');
app.engine('hbs', hbs.engine)

var options = {}
var cookieSettings = {
    path: '/',
    maxAge: 120 * 1000,
}

var startAsHTTPS = true
try {

    // this is required to start in HTTPS mode
    options.key = fs.readFileSync(path.resolve(__dirname, '../config/server.key'), 'utf8');
    options.cert = fs.readFileSync(path.resolve(__dirname, '../config/server.crt'), 'utf8');

    cookieSettings.sameSite = 'none'
    cookieSettings.secure = true

} catch (err) {
    startAsHTTPS = false
    options = {}
    cookieSettings.secure = false
}

app.use(session({
    secret: 'supersecret',
    resave: false,
    saveUninitialized: true,
    cookie: cookieSettings
}))

// define routes
app.use(express.static(__dirname + '/../public'))
app.use('/', sessionRoutes);
app.use('/users', usersRoutes);

if (startAsHTTPS) {

    // Create HTTPS server
    const server = https.createServer(options, app);

    server.listen(PORT, () => {
        console.log('HTTPS Server started and listening on port 3000');
    });

} else {

    app.listen(PORT, () => {
        console.log('HTTP Server started and listening on port 3000');
    });

}