// load contents of .env into process.env
require('dotenv').config();

let clientAuthMethod = process.env.CLIENT_AUTH_METHOD;
if (clientAuthMethod == null || clientAuthMethod == "") {
    clientAuthMethod = "client_secret_post";
}
exports.Config = {
    tenantUrl           : process.env.TENANT_URL,
    discoveryUrl        : process.env.DISCOVERY_URL,
    clientId            : process.env.CLIENT_ID,
    clientSecret        : process.env.CLIENT_SECRET,
    redirectUri         : process.env.REDIRECT_URI,
    scope               : process.env.SCOPE,
    signupLink          : process.env.USER_REGISTRATION_LINK,
    themeId             : process.env.THEME_ID,
    clientAuthMethod    : clientAuthMethod,
    usePar              : process.env.USE_PAR,
    useDPoP             : process.env.USE_DPOP,
    resourceBase        : process.env.RESOURCE_BASE_URL,
    deviceName          : process.env.DEVICE_NAME,
};
