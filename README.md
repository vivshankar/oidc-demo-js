# OIDC Demo

Use this application to configure your first OIDC application for client authentication. The application is built with Node.js and uses [openid-client](https://www.npmjs.com/package/openid-client). All UI assets can be found under [views](/views) and [public](/public). All views are written using vanilla HTML and JS and templated using Handlebars.

In this app, you can do the following -

1. Authenticating the client using a configured OIDC OP
2. Logging out of the client
3. Viewing the authenticated user's profile by unpacking the id_token

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

1. Generate client credentials on a OIDC OP server. Choose the grant type as authorization code, set redirect_uri to `http://localhost:3000/auth/callback` and disable PKCE validation.

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