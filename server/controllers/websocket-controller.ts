import { Server as WebSocketServer } from 'ws';
import { ExtendedWebSocket, WebSocketMessage } from '../types/websocket.types.js';

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
        const msg: WebSocketMessage = JSON.parse(data);

        switch (msg.method) {
          case 'connection':
            this.connectionHandler(ws, msg);
            break;
          case 'draw':
            this.broadcastMessage(ws, msg);
            break;
          default:
            console.warn(`Unknown method: ${msg.method}`);
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
    msg: WebSocketMessage,
  ): void => {
    ws.id = msg.id;
    this.broadcastMessage(ws, msg);
  };

  private broadcastMessage = (
    ws: ExtendedWebSocket,
    msg: WebSocketMessage,
  ): void => {
    this.wss.clients.forEach((client) => {
      const extendedClient = client as ExtendedWebSocket;
      if (extendedClient.id === msg.id && client.readyState === client.OPEN) {
        client.send(JSON.stringify(msg));
      }
    });
  };
}

export default WebSocketController;
