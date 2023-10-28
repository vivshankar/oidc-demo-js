const config = require('./config').Config;
const Issuer = require('openid-client').Issuer
const generators = require('openid-client').generators
const { uuid } = require('uuidv4');
const fs = require('fs');
const path = require("path");
const jwt = require('jsonwebtoken')
const crypto = require('crypto');
const HTTPUtil = require('../services/httputil');
const resourceClient = new HTTPUtil(config.resourceBase);

var dpopKeyPair = {
    publicKey: null,
    privateKey: null,
}

class OAuthController {

    constructor(scope) {
        this._scope = scope;
        this._jwks = undefined;

        if (config.clientAuthMethod == "private_key_jwt") {
            try {
                const data = fs.readFileSync(path.resolve(__dirname, `../../config/jwks.json`), 'utf8');
                this._jwks = { "keys": JSON.parse(data) };
            } catch (err) {
                console.warn(err);
                throw "jwks.json is not configured but client auth method is configured to use 'private_key_jwt'"
            }
        }
    }

    resource = async (req, res) => {
        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/')
            return;
        }

        let tokenSet = OAuthController.getAuthToken(req);
        // Make a call to the resource API protected by DPoP to test
        var dpopProof = ""
        var authHeader = `Bearer ${tokenSet.access_token}`;
        if (config.useDPoP == "true") {
            var key = crypto.createPrivateKey({
                key: dpopKeyPair.privateKey,
                format: 'jwk'
            });

            const ath = crypto.createHash('sha256')
                   .update(tokenSet.access_token)
                   .digest('base64url');

            var currentTimestamp = new Date().getTime()/1000;
            var payload = {
                "jti": uuid(),
                'iat': currentTimestamp,
                'exp': currentTimestamp + 1*1800,
                "htm": "GET",
                "htu": `${config.resourceBase}/photos`,
                "ath": ath
            };

            dpopProof = await this._client.dpopProof(payload, key, tokenSet.access_token);
            console.log(`DPoP proof for the resource API call=${dpopProof}`);

            authHeader = `DPoP ${tokenSet.access_token}`;
        }

        let response = await resourceClient.get('/photos', {
            "tenant": config.tenantUrl,
            "Authorization": authHeader,
            "dpop": dpopProof,
        });

        console.log(`\n\n=======\nResponse from the resource API /photos\n=======\n\n${response.data}\n`);
        res.send(response.data);
    }

    authorize = async (req, res) => {
        this._oidcIssuer = await Issuer.discover(config.discoveryUrl);
        console.log('Discovered issuer %s %O', this._oidcIssuer.issuer, this._oidcIssuer.metadata);

        let url = ""
        const code_verifier = generators.codeVerifier();
        const code_challenge = generators.codeChallenge(code_verifier);

        req.session.codeVerifier = code_verifier;
        req.session.save();

        if (config.usePar != "true") {
            this._client = new this._oidcIssuer.Client({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uris: [config.redirectUri],
                response_types: ['code'],
                token_endpoint_auth_method: config.clientAuthMethod,
                token_endpoint_auth_signing_alg: 'PS256',
            }, this._jwks);
    
            url = this._client.authorizationUrl({
                scope: this._scope,
                state: uuid(),
                code_challenge,
                code_challenge_method: 'S256',
            });
        } else {
            this._client = new this._oidcIssuer.FAPI1Client({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uris: [config.redirectUri],
                response_types: ['code'],
                token_endpoint_auth_method: 'private_key_jwt',
                token_endpoint_auth_signing_alg: 'PS256',
                tls_client_certificate_bound_access_tokens: false,
                id_token_signed_response_alg: 'RS256',
            }, this._jwks);

            // build JWT
            let parData = await this._client.pushedAuthorizationRequest({
                scope: this._scope,
                state: uuid(),
            }, {
                clientAssertionPayload: { 
                    sub: config.clientId, 
                    iss: config.clientId,
                    jti: uuid(),
                    iat: new Date().getTime()/1000,
                    exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                    aud: this._oidcIssuer.metadata.token_endpoint,
                },
            });

            url = this._client.authorizationUrl({
                request_uri: parData.request_uri,
                code_challenge,
                code_challenge_method: 'S256',
            });
        }
        
        var parsedURL = new URL(url);
        parsedURL.searchParams.append('deviceName', config.deviceName);

        res.redirect(parsedURL.toString())
    }

    aznCallback = async (req, res) => {
        const params = this._client.callbackParams(req);
        var clientAssertionPayload = null
        if (config.usePar == "true") {
            clientAssertionPayload = { 
                sub: config.clientId, 
                iss: config.clientId,
                jti: uuid(),
                iat: new Date().getTime()/1000,
                exp: (new Date().getTime() + 30 * 60 * 1000)/1000,
                aud: this._oidcIssuer.metadata.token_endpoint,
            }
        }

        let key = null; 
        if (config.useDPoP == "true") {
            const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
                modulusLength: 4096,
                publicKeyEncoding: {
                  type: 'spki',
                  format: 'jwk'
                },
                privateKeyEncoding: {
                  type: 'pkcs8',
                  format: 'jwk',
                  cipher: 'aes-256-cbc',
                  passphrase: uuid(),
                }});

            dpopKeyPair = {
                publicKey: publicKey,
                privateKey: privateKey,
            }

            key = crypto.createPrivateKey({
                key: dpopKeyPair.privateKey,
                format: 'jwk'
            });
        }
        
        let codeVerifier = req.session.codeVerifier;
        const tokenSet = await this._client.callback(config.redirectUri, params, {
            state: params.state,
            code_verifier: codeVerifier,
        }, {
            clientAssertionPayload: clientAssertionPayload,
            DPoP: key,
        });
        console.log(`Received and validated tokens\n${JSON.stringify(tokenSet, null, 2)}\n`);
        console.log('Validated ID Token claims %j', tokenSet.claims());

        req.session.authToken = tokenSet;
        req.session.token = tokenSet;
        req.session.save();

        // Extract redirect URL from querystring
        let targetUrl = req.session.targetUrl;
        if (!targetUrl || targetUrl == "") {
            targetUrl = "/";
        }

        // redirect to authenticated page
        res.redirect(targetUrl);
    }

    logout = (req, res) => {

        if (!OAuthController.isLoggedIn(req)) {
            res.redirect('/')
            return;
        }

        req.session.destroy();
        const proxyHost = req.headers["x-forwarded-host"];
        const host = proxyHost ? proxyHost : req.headers.host;
        res.redirect('https://' + config.tenantUrl + '/idaas/mtfim/sps/idaas/logout?redirectUrl=' + encodeURIComponent(req.protocol + '://' + host) + "&themeId=" + config.themeId);
    }

    static isLoggedIn(req) {
        return req.session != null && req.session.authToken != null && req.session.authToken != "";
    }

    static getAuthToken = (req) => {
        if (req.session) {
            return req.session.authToken
        }
    
        return null;
    }

    static getUserPayload = (req) => {
        let authToken = OAuthController.getAuthToken(req);
        let decoded = jwt.decode(authToken.id_token);
        return decoded;
    }
}

module.exports = OAuthController;