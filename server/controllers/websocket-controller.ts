import { Server as WebSocketServer } from 'ws';
import {
  ExtendedWebSocket,
  WsMessage,
  WsMessageSchema,
  ConnectionMessage,
} from '../types/websocket.types.js';

class WebSocketController {
  private wss: WebSocketServer;

  constructor(wss: WebSocketServer) {
    this.wss = wss;
  }

  handleConnection = (ws: ExtendedWebSocket): void => {
    console.log('Connection established');
    ws.send('You are successfully connected');

    ws.on('message', (data: string) => {
      try {
        const parsed: unknown = JSON.parse(data.toString());
        const parseResult = WsMessageSchema.safeParse(parsed);
        if (!parseResult.success) {
          console.error('Invalid WS message received:', parseResult.error);
          return;
        }

        const msg = parseResult.data as WsMessage;

        switch (msg.method) {
          case 'connection': {
            // msg is narrowed to ConnectionMessage here by discriminated union
            this.connectionHandler(ws, msg as ConnectionMessage);
            break;
          }
          case 'draw': {
            this.broadcastMessage(ws, msg);
            break;
          }
          default: {
            console.warn(`Unknown method: ${(msg as any).method}`);
          }
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    });

    ws.on('close', () => {
      console.log('Connection closed');
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  };

  private connectionHandler = (
    ws: ExtendedWebSocket,
    msg: ConnectionMessage,
  ): void => {
    ws.id = msg.id;
    ws.username = msg.username;

    // Broadcast to all clients in the same room that a user connected
    const broadcastPayload: ConnectionMessage = {
      method: 'connection',
      id: msg.id,
      username: msg.username,
    };

    this.broadcastMessage(ws, broadcastPayload);
  };

  private broadcastMessage = (ws: ExtendedWebSocket, msg: WsMessage): void => {
    const READY_STATE_OPEN = 1;

    this.wss.clients.forEach((client) => {
      const extendedClient = client as ExtendedWebSocket;
      if (
        extendedClient.id === msg.id &&
        client.readyState === READY_STATE_OPEN
      ) {
        client.send(JSON.stringify(msg));
      }
    });
  };
}

export default WebSocketController;
