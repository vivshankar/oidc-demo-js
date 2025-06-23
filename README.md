# OIDC Demo

Use this application to configure your first OIDC application for client authentication. You can also toggle on more advanced use cases to learn about how to protect your APIs with stronger controls. 

This application is built with Node.js and uses [openid-client](https://www.npmjs.com/package/openid-client). All UI assets can be found under [views](/views) and [public](/public). All views are written using vanilla HTML and JS and templated using Handlebars.

In this app, you can do the following -

1. Authenticating the client using a configured OIDC OP
2. Logging out of the client
3. Viewing the authenticated user's profile by unpacking the id_token
4. Trigger single-logout (SLO)

You can also run this in two modes:

1. Using standard authorization code flow with the `client_secret_post` authentication method.
2. Using pushed authorization request with the `private_key_jwt` authentication method, which is more suited for Open Banking use cases.

## Pre-requisites

1. Install Node and Git on your machine
2. Clone this repo to your machine

## Setup

There are two possible configurations supported:

1. Standard authorization code flow
2. More tailored and secure Open Banking compliant flow

### Standard authorization code flow

1. Generate client credentials on a OIDC OP server. Choose the grant type as authorization code and set redirect_uri to `http://localhost:3000/auth/callback`.

2. Copy `dotenv` file to `.env` and populate the values as below
    - `DISCOVERY_URL`: Set the Open ID Connect discovery (well-known) endpoint here
    - `CLIENT_ID`: The OIDC client ID generated on step 1
    - `CLIENT_SECRET`: The OIDC client secret generated on step 1
    - `SCOPE`: If you aren't sure what to set here, just set this as `openid profile email`

### Open banking compliant flow

1. Generate client credentials on a OIDC OP server with the following settings:
    - `Authorization code` grant type allowed
    - `private_key_jwt` client authentication method
    - Pushed authorization request supported and allowed

2. Copy `dotenv` file to `.env` and populate the values as below
    - `DISCOVERY_URL`: Set the Open ID Connect discovery (well-known) endpoint here
    - `CLIENT_ID`: The OIDC client ID generated on step 1
    - `CLIENT_SECRET`: The OIDC client secret generated on step 1
    - `SCOPE`: If you aren't sure what to set here, just set this as `openid profile email`
    - `USE_PAR`: Set to "true"

### Set up for Single-Logout

This application is using cookie to store the session. In order to logout properly, cookie information need to be received.
The application is using front-channel logout endpoint, which is called by authorization server (OP) using `iframe`.

Modern browser will not forward cookie to unsecure site. Hence the application need to start in HTTPS mode.

1. Assuming this application is accessible as `demoapp.com`. You can create alias in `/etc/hosts` for your localhost IP.

2. Generate HTTP server key and certificate as shown below and place it under `config` folder.

```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./server.key -out server.crt \
-subj "/CN=demoapp.com" -addext "subjectAltName=DNS:demoapp.com,IP:127.0.0.1"
```

3. Add the certificate as trusted certificate for your browser.

4. Since `demoapp.com` is not the same domain or a sub-domain of IBM Security Verify site, `demoapp.com` cookie is considered a third-party cookie for IBM Security Verify. In order for the `demoapp.com` cookie get forwarded in `iframe`, IBM Security Verify has to allow third-party cookie.

5. Edit `.env` and populate the following values:
    - POST_LOGOUT_REDIRECT_URI=https://demoapp.com:3000/postlogout
    - USE_RP_INIT_LOGOUT=true

## Run the application

1. Install node dependencies

    ```bash
    npm install
    ```

2. Run the application. You should see `Server started and listening on port 3000` after executing the command below.

    ```bash
    npm start
    ```

3. Open the browser and go to http://localhost:3000 and you should be able to use the application. Click Login and away you go.