import WebSocket from 'ws';
import { z } from 'zod';

export type FigureType = 'brush' | 'rect' | 'circle' | 'eraser';

export interface Point {
  x: number;
  y: number;
}

export interface Figure {
  type: FigureType;
  x: number;
  y: number;
  width?: number;
  height?: number;
  radius?: number;
  color?: string;
  strokeWidth?: number;
  points?: Point[];
}

export interface ConnectionMessage {
  method: 'connection';
  id: string; // room/session id
  username: string;
}

export interface DrawMessage {
  method: 'draw';
  id: string; // room/session id
  figure: Figure;
}

export type WsMessage = ConnectionMessage | DrawMessage;

export interface ExtendedWebSocket extends WebSocket {
  id?: string; // room id
  username?: string;
}

// Zod schemas for runtime validation
export const PointSchema = z.object({
  x: z.number(),
  y: z.number(),
});

export const FigureSchema = z.object({
  type: z.enum(['brush', 'rect', 'circle', 'eraser']),
  x: z.number(),
  y: z.number(),
  width: z.number().optional(),
  height: z.number().optional(),
  radius: z.number().optional(),
  color: z.string().optional(),
  strokeWidth: z.number().optional(),
  points: z.array(PointSchema).optional(),
});

export const ConnectionMessageSchema = z.object({
  method: z.literal('connection'),
  id: z.string(),
  username: z.string(),
});

export const DrawMessageSchema = z.object({
  method: z.literal('draw'),
  id: z.string(),
  figure: FigureSchema,
});

export const WsMessageSchema = z.discriminatedUnion('method', [
  ConnectionMessageSchema,
  DrawMessageSchema,
]);

export type WsMessageSchemaType = z.infer<typeof WsMessageSchema>;
