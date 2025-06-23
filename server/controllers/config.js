// load contents of .env into process.env
require('dotenv').config();

let clientAuthMethod = process.env.CLIENT_AUTH_METHOD;
if (clientAuthMethod == null || clientAuthMethod == "") {
    clientAuthMethod = "client_secret_post";
}

let deviceName = process.env.DEVICE_NAME;
if (deviceName == null || deviceName == "") {
    deviceName = ""
}

let extraRequestParams = process.env.EXTRA_REQUEST_PARAMS;
if (extraRequestParams != null && extraRequestParams != "") {
    extraRequestParams = JSON.parse(extraRequestParams);
    Object.keys(extraRequestParams).forEach(function(key) {
        if (extraRequestParams[key] != null && typeof extraRequestParams[key] === "object") {
            extraRequestParams[key] = JSON.stringify(extraRequestParams[key]);
        }
    })
} else {
    extraRequestParams = {};
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
    postLogoutUri       : process.env.POST_LOGOUT_REDIRECT_URI,
    useRPInitLogout     : process.env.USE_RP_INIT_LOGOUT,
    deviceName          : deviceName,
    extraRequestParams  : extraRequestParams,
};
