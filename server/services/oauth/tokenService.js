const config = require('../../controllers/config').Config;
const HTTPUtil = require('../httputil');
const httpClient = new HTTPUtil(`https://${config.tenantUrl}`);
        
class TokenService {

    introspect = async (accessToken) => {
        const response = await httpClient.post('/oauth2/introspect', {
            "client_id": config.clientId,
            "client_secret": config.clientSecret,
            "token": accessToken,
        }, {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
        });

        return response.data;
    }
}

module.exports = TokenService;