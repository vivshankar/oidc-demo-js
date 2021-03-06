const config = require('./config').Config;
const Issuer = require('openid-client').Issuer
const { uuid } = require('uuidv4');
const jwt = require('jsonwebtoken')

class OAuthController {

    constructor(scope) {
        this._scope = scope;
    }

    authorize = async (req, res) => {
        this._oidcIssuer = await Issuer.discover(config.discoveryUrl);
        console.log('Discovered issuer %s %O', this._oidcIssuer.issuer, this._oidcIssuer.metadata);

        let url = ""
        if (config.usePar != "true") {
            this._client = new this._oidcIssuer.Client({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uris: [config.redirectUri],
                response_types: ['code'],
                token_endpoint_auth_method: 'client_secret_post'
            });
    
            url = this._client.authorizationUrl({
                scope: this._scope,
                state: uuid(),
            });
        } else {
            // generated from https://mkjwk.org/
            var keys = {
                "keys": [
                    {
                        "p": "z1Mklvta_Kw1q79PMhK7nHGVMIToyx9YPKjECQCAaDo02xCZCOBz-Tnv6NTwwsdoHKU4CjSf7TdD7_zpTaieyIkPRXPnMlSCMt626fD58EnIwvKJtTCwzHz8dbt7lH6ihq4xD4NNbE2xUiP6HjKGWyUM6RuNRSpfXPbEAmbslpU",
                        "kty": "RSA",
                        "q": "xH0o7t617m4Ec5lD2gMcFDH_VuNI-p2RvDAF60pOA-NRryJhwqJkbTCAeUAeaybh1Cv3cB3Tdl-10OpriS5rl62vmhVZUwaUhGstjwTUUBTTRkl7vIEwHWvWXtcpHaxbP2DV11OJhToAndbcVvAoOCmYKRtasbmlVletM9T9Nj8",
                        "d": "k5r2JrDPCL5mBoTlfOPb1P45scJyXVF5ynLqfQX8hGhhYgvtg3AnTEzqbnTUdzSoMzIv0PUW6p1UGtw6AUL_Ts6bLL1xivgOIBKK1mmt0x9avl1JcpewELTT81FQ8f4E0ORXB-m9ZNYUhjH7Rs5hTI7zddnKQ5XJxMykSoEDjIdym-aptmUh0Y8UczQakSTkjopyZqQPu2vl4BMXxpXvj9pTaBRb_wG7vOdibdGlAnNRZosER5o7aK0o_bRwSeGEAQs-5A9AvJFt1twMJMEAowzih8r_fas0OXJ1dbs_QZfx35wqJ8MqwOImXLnoDxjOd2WAVc1hwCjkVpWUjki1aQ",
                        "e": "AQAB",
                        "use": "sig",
                        "kid": "demojwtsigner",
                        "qi": "b8cxjehpQBHuFGLJ1sbkvxwNR1YZZnn3T5biH6KtZG2WWHBGs4596_4Iy8NRiRnRLc4fnKiVKyVVBvXZgpl7CtR50tYy0HMidVgU4TCNF7F50q03Hfq42AGypvBYeHZMtSKGbpwKWLgjBG-pEbjlkKIkceTG5cLITr7EuO0EAQs",
                        "dp": "hwoRuCHqZs_IeaC3ddcLyl-VHDBF7R_yejg2z-I6wSjAirup4kVIZNoe8NnaJBR8NMRM1yDl1j38C1IBqGqfWeEkSEmxGnA_CeFU5NXoBmIY2RnfJlybm-YBDrJaUSOWuwC0xfTxNgz45Za3cHnaV32vhhpDDv0FdmjozOO7UG0",
                        "alg": "RS256",
                        "dq": "cm-WnHBXMzMeIplb3Cg9fUGVPeyHv3Zvv1OUzvFquHb3RvHWT_42USWTXYrLbIqrsd-db83fL60UfkVZNf80KJW-lRXj_Sfy7aBiW05rvOw0FFaN2z6-YBRDON9FEgQk7KegQ5VinZYnb8YIdBXQxszq0t4cly_RLJVJycs9Yg8",
                        "n": "nyEEwueLcSFRUSPdy9AL5Vf6X7QDuL8mFMOR2liM1LeluSHCSYIoN-h6xxMkwDfr6626EOhJVxMxeBuLaG-_3QWWjvicUdIpevj73U1jqQT7MaMPI3ms7rm0v1OHfabyLbrCjDniL_8Ym15H_RwVqF31kXIcKVqMtJWRWkeoOrSSqUq4h28rRDUi8HXUTAvSoQYnZ-J-sICME7G-ZYVJtIQObT6AjMuM_y54vCH8ViVE9aOQ2rV3Wi-TKEgiV9Ik1KB6EdzCB4CYK2HYy_OgheF0ggeWuwHOegBpVR4BqlQyZJKJyhKhWZhfYHmWkm_V-7KZtrWHoVQ_NhOAcT18qw"
                    }
                ]
            }
            
            this._client = new this._oidcIssuer.FAPI1Client({
                client_id: config.clientId,
                client_secret: config.clientSecret,
                redirect_uris: [config.redirectUri],
                response_types: ['code'],
                token_endpoint_auth_method: 'private_key_jwt',
                token_endpoint_auth_signing_alg: 'RS256',
                tls_client_certificate_bound_access_tokens: false,
                id_token_signed_response_alg: 'RS256',
            }, keys);

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
            });
        }
        
        res.redirect(url)
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
        const tokenSet = await this._client.callback(config.redirectUri, params, {
            state: params.state
        }, {
            clientAssertionPayload: clientAssertionPayload,
        });
        console.log('received and validated tokens %j', tokenSet);
        console.log('validated ID Token claims %j', tokenSet.claims());

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

        let authToken = OAuthController.getAuthToken(req);
        this._authClient.revokeToken(authToken, 'access_token').then(response => {

        }).catch(error => {
            console.log(error);
        })
        
        // revoking the refresh_token
        this._authClient.revokeToken(authToken, 'refresh_token').then(response => {
        
        }).catch(error => {
            console.log(error);
        })

        req.session.destroy();
        const proxyHost = req.headers["x-forwarded-host"];
        const host = proxyHost ? proxyHost : req.headers.host;
        res.redirect(config.tenantUrl + '/idaas/mtfim/sps/idaas/logout?redirectUrl=' + encodeURIComponent(req.protocol + '://' + host) + "&themeId=" + config.themeId);
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
}

module.exports = OAuthController;