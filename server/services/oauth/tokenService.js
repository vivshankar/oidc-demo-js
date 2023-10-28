const config = require('../../controllers/config').Config;
const Issuer = require('openid-client').Issuer
const fs = require('fs');
const path = require("path");
        
class TokenService {

    introspect = async (accessToken) => {
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

        this._oidcIssuer = await Issuer.discover(config.discoveryUrl);
        this._client = new this._oidcIssuer.Client({
            client_id: config.clientId,
            client_secret: config.clientSecret,
            token_endpoint_auth_method: config.clientAuthMethod,
            token_endpoint_auth_signing_alg: 'PS256',
        }, this._jwks);

        const response = await this._client.introspect(accessToken, "access_token");
        return JSON.parse(JSON.stringify(response));
    }
}

module.exports = TokenService;