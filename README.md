# Web Server

This folder contains a minamalist server for authenticating using msal in a confidential client application.
That is, the user will not be served any UI until after a valid session is established.
It uses encrypted cookies to keep track of pre-login state, not creating any sessions until after authentication.
After login, it uses a signed cookie to identify the session.
The OAUTH tokens are saved encrypted to the session store, separate from the session itself.

To use it, some sort of build process will need to copy your UI in to the `build/dist` folder.
At a minimum, create `build/dist/index.html` just so the server has something to return.
The `build` folder is where the built server goes. The `build/dist` is where static content goes.

It was built to be used with an SPA, so any url outside of `/api` that also does
not have a match in the static content will return `build/dist/index.js`.
This can easily be changed in index.

The way it is currently set up will only allow returning an access token for 1 scope.
If multiple are needed, change the getToken related code as appropriate.

## Why a Confidential Client for an SPA?

Because of business requirements.

## Setup Environment Variables

Copy `.env.sample` to `.env`.
Edit this file to fill in the needed secrets.
Never commit the secrets.

## To Run The Server

- To run the server from a stand-alone command prompt:
  - From `server` folder, run `npm run build` to build sever's typescript
  - From `server` folder, run `npm start` to launch the server
- To run the server from VSCode:
  - Launch the `Debug Server` configuration from VSCodes debug menu.
    This will build and then launch the server in VSCodes debug console.
- Access the server on http://localhost:8889
