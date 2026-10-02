import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { driveConfigSchema } from './drive.js';

export const configSchema = z.object({
  roots: z.array(z.object({
    id: z.string().regex(/^[a-zA-Z0-9_-]{1,40}$/),
    path: z.string().min(1), label: z.string().min(1).max(100),
    allowCreate: z.boolean().optional(),allowShare:z.boolean().optional()
  }).strict()).max(20).default([]),
  http: z.object({
    host: z.string().default('127.0.0.1'), port: z.number().int().min(1).max(65535).default(8787),
    allowedHosts: z.array(z.string().min(1)).min(1).default(['127.0.0.1', 'localhost']),
    allowedOrigins: z.array(z.string().url()).default([]),
    tokenFile: z.string().min(1),
    maxConcurrent: z.number().int().min(1).max(32).default(4),
    requestsPerMinute: z.number().int().min(1).max(1000).default(120)
  }).strict(),
  limits: z.object({
    maxReadBytes: z.number().int().min(1).max(2_000_000).default(262144),
    maxEntries: z.number().int().min(1).max(20000).default(5000),
    maxDepth: z.number().int().min(0).max(32).default(8),
    timeoutMs: z.number().int().min(10).max(30000).default(5000)
  }).strict().default({}),
  denyNames: z.array(z.string().min(1)).default([]),
  drive:driveConfigSchema.optional(),
  management: z.object({secretFile: z.string().min(1)}).strict().optional()
}).strict().superRefine((c, ctx) => {
  if (new Set(c.roots.map(r => r.id)).size !== c.roots.length)
    ctx.addIssue({code: 'custom', message: 'Root IDs must be unique'});
});
export type Config = z.infer<typeof configSchema>;
export async function loadConfig(path: string): Promise<Config> {
  return configSchema.parse(JSON.parse(await readFile(path, 'utf8')));
}
