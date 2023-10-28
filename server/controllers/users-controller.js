const jwt = require('jsonwebtoken')
const OAuthController = require('./oauth-controller');
const Privacy = require('verify-privacy-sdk-js');
const config = require('./config').Config;
const TokenService = require('../services/oauth/tokenService')
const tokenService = new TokenService();

class UsersController {

    constructor() {}

    getUserPayload = (req) => {
        let authToken = OAuthController.getAuthToken(req);
        let decoded = jwt.decode(authToken.id_token);
        return decoded;
    }

    getUsersIndex = (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return null;
        }

        res.render('users', { user: this.getUserPayload(req), title: 'User Main' });
    }

    introspect = async (req) => {
        let authToken = OAuthController.getAuthToken(req);
        const data = await OAuthController.introspect(authToken.access_token)
        console.log(`Introspection payload=\n${JSON.stringify(data, null, 2)}\n`);
        return data;
    };

    getProfile = async (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return;
        }

        let idTokenPayload = this.getUserPayload(req);
        let introspection = await this.introspect(req);
        res.render('profile', { 
            user: idTokenPayload, 
            fullJson: JSON.stringify(idTokenPayload, null, 4), 
            introspection: JSON.stringify(introspection, null, 2), 
            title: 'Profile Information' 
        });
    }

    getConsents = (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/');
            return;
        }

        let idTokenPayload = this.getUserPayload(req);
        let auth = {
            accessToken: OAuthController.getAuthToken(req).access_token
        }

        let dpcmClient = new Privacy(config, auth, {})
        dpcmClient.getUserConsents(auth).then(result => {
            res.render('consents', { user: idTokenPayload, consents: result.consents, title: 'My Consents' });
        }).catch(err => {
            console.log("Error=" + err);
            res.render('consents', { user: idTokenPayload, consents: null, title: 'No consents found' });
        })
    }
}

module.exports = UsersController;