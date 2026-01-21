import WebSocket from 'ws';

export interface ExtendedWebSocket extends WebSocket {
  id?: string;
}

export interface WebSocketMessage {
  method: 'connection' | 'draw';
  id: string;
  [key: string]: any;
}
