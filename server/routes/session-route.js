// import dependencies and initialize the express router
const express = require('express');
const OAuthController = require('../controllers/oauth-controller');
const config = require('../controllers/config').Config;

const oauthController = new OAuthController(config.scope);
const router = express.Router();

// define routes
router.get('/',  (req, res) => {
    if (OAuthController.isLoggedIn(req)) {
        res.redirect('/users');
    } else {
        res.render('index', {title: 'Verify OIDC Demo', signupEnabled: config.signupLink != "", signupLink: config.signupLink })
    }
});

router.get('/login', oauthController.authorize);
router.get('/logout', oauthController.logout)
router.get('/resource', oauthController.resource)
router.get('/auth/callback', oauthController.aznCallback);
router.get('/fclogout', oauthController.frontChannelCallback);
router.get('/bclogout', oauthController.backChannelCallback);
router.get('/postlogout', oauthController.postLogoutCallback);

module.exports = router;