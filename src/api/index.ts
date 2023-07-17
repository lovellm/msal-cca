import express from "express";
import heartbeat from "./heartbeat";
import { AuthProvider } from "../msal/AuthProvider";

export default function (authProvider: AuthProvider) {
  const apiRouter = express.Router();

  apiRouter.get("/heartbeat", heartbeat);
  apiRouter.get("/accessToken", (req, res) => {
    authProvider.getToken(req, res);
  });
  apiRouter.get("/refreshAccessToken", (req, res) => {
    authProvider.getToken(req, res, true);
  });

  return apiRouter;
}
