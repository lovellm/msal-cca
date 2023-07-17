import * as dotenv from "dotenv";
import express, { Request, Response } from "express";
import path from "path";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import helmet from "helmet";
import setupSession from "./src/auth/setupSession";
import api from "./src/api";

dotenv.config();
const port = 8889;

async function startApp() {
  const app = express();
  app.set("x-powered-by", false);

  // Use common middleware
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          "default-src": ["'self'" /*, "Other hosts your ui retrieves data from go here"*/],
        },
      },
    }),
  );
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  // Set up Session and Authentication
  const authProvider = await setupSession(app);

  // Add any api routes
  app.use("/api", api(authProvider));

  // Serve anything in /dist as a static file
  app.use(express.static(path.resolve(__dirname, "dist")));

  // Replace root with index.html
  app.get("/", (req, res) => {
    res.redirect("/index.html");
  });

  // Function to send other valid url patterns to index (assuming SPA front-end)
  const sendToIndex = (req: Request, res: Response) => {
    res.sendFile(path.resolve(__dirname, "dist", "index.html"));
  };

  // For now, send anything to index.
  // If need other server-side routes or server-side 404s, remove this and add those instead
  app.get("*", sendToIndex);

  // Start the server
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Listening on port: ${port}`);
  });
}

startApp();
