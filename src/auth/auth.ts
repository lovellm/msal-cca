import { Express } from "express";
import { AuthProvider } from "../msal/AuthProvider";
import { getUrlCookie } from "./checkAuth";

export default function (app: Express, authProvider: AuthProvider) {
  // Register /auth/login to initiate an authenticate request.
  app.get("/auth/login", (req, res) => {
    authProvider.signIn(req, res);
  });

  app.post(
    "/auth/openid/return",
    (req, res, next) => {
      authProvider.handleRedirect(req, res, next);
    },
    (req, res) => {
      if (req.session?.account) {
        // eslint-disable-next-line no-console
        console.log("Return from AzureAD " + req.session.account.name);
      }

      // If we have an original url cookie, redirect to that instead of root
      const cookieName = getUrlCookie();
      const cookies = req.cookies || {};
      const redirectUrl = cookies[cookieName];
      if (redirectUrl && redirectUrl !== "/") {
        res.clearCookie(cookieName);
        return res.redirect(redirectUrl);
      }

      return res.redirect("/");
    },
  );

  // 'logout' route, logout and destroy the session
  app.get("/auth/logout", (req, res) => {
    if (req.session) {
      req.session.destroy(() => {
        res.status(200).send(`
          <!DOCTYPE html>
          <html lang="en">
            <head><meta charset="utf-8" /><title>Logged out</title></head>
            <body>
              <div>
                You have logged out.
              </div>
            </body>
          </html>`);
      });
    } else {
      res.status(200).send(`
        <!DOCTYPE html>
        <html lang="en">
          <head><meta charset="utf-8" /><title>Logged out</title></head>
          <body>
            <div>
              You have logged out (No Session Existed).
            </div>
          </body>
        </html>`);
    }
  });

  // A POST to logout, destroy the session and return empty success response
  app.post("/auth/logout", (req, res) => {
    if (req.session) {
      req.session.destroy(() => {
        res.status(200);
        res.setHeader("Content-Length", "0");
        res.send();
      });
    } else {
      res.status(200);
      res.setHeader("Content-Length", "0");
      res.send();
    }
  });

  // If Auth Failed, Render a Basic Failure page
  app.get("/auth/failed", (req, res) => {
    res.status(403).send(`
      <!DOCTYPE html>
      <html lang="en">
        <head><meta charset="utf-8" /><title>Unauthorized</title></head>
        <body>
          <div>
            You are not authorized to access the application.
          </div>
        </body>
      </html>`);
  });
}
