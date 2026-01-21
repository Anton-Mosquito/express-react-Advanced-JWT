import "dotenv/config";
import express, { Application } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import router from "./route/index";
import errorMiddleware from "./middleware/error-middleware";
import expressWs, { Application as WebSocketApplication } from "express-ws";
import WebSocketController from "./controllers/websocket-controller";
import { ExtendedWebSocket } from "./types/websocket.types";
import { env } from "./config/env";

const PORT: number = env.PORT;

const app = express();
const wsInstance = expressWs(app);
const wsApp = wsInstance.app as WebSocketApplication;
const wss = wsInstance.getWss();

const wsController = new WebSocketController(wss);

wsApp.use(express.json());
wsApp.use(cookieParser());
wsApp.use(
  cors({
    credentials: true,
    origin: env.CLIENT_URL,
  }),
);
wsApp.use("/api", router);
wsApp.use(errorMiddleware);

wsApp.ws("/", (ws: ExtendedWebSocket) => {
  wsController.handleConnection(ws);
});

const start = async () => {
  try {
    wsApp.listen(PORT, () => console.log(`Server work on PORT ${PORT}`));
  } catch (error) {
    console.log(error);
  }
};

start();
