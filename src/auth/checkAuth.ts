import { Request, Response, NextFunction } from "express";

export function getUrlCookie() {
  return (process.env.APP_NAME || "APP") + "_URL";
}

export default function checkAuth(req: Request, res: Response, next: NextFunction) {
  const urlPath = req.originalUrl || "";

  // See if currently authenticated via passport
  const isAuth = req.session.isAuthenticated;

  // If authenticated or a non-protected resource, continue middleware chain
  if (
    isAuth ||
    urlPath.startsWith("/auth") ||
    urlPath === "/manifest.json" ||
    urlPath === "/favicon.ico" ||
    urlPath.startsWith("/robots")
  ) {
    return next();
  }

  // If trying to access an api endpoint without already being logged in, give error instead of trying to log in
  if (urlPath.startsWith("/api")) {
    res.status(401);
    return res.send("You must be logged in to access this");
  }

  // Set the requested URL in a cookie so we can redirect back to it after logging in
  if (urlPath !== "/") {
    const cookieName = getUrlCookie();
    res.cookie(cookieName, urlPath, {
      httpOnly: true,
      // maxAge property does not get set properly, expires does
      expires: new Date(new Date().valueOf() + 180000),
    });
  }

  // Redirect to Login
  return res.redirect("/auth/login");
}
