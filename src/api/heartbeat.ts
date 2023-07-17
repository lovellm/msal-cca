import { Request, Response } from "express";

export default async function checkAuth(req: Request, res: Response) {
  res.status(200);
  return res.send(`Server is alive: ${new Date().toUTCString()}`);
}
