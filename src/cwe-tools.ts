import { tool } from 'ai';
import { z } from 'zod';
import { getCweList } from './enricher.js';

// Raw Zod schemas for validation in tests and elsewhere
export const findCweByIdSchema = z.object({ id: z.string().regex(/^\d+$/).max(10) });
export const findCweByNameSchema = z.object({ keyword: z.string().min(2).max(100) });
export const findCweByCapecSchema = z.object({ capec_id: z.string().regex(/^\d+$/).max(10) });

export const cweTools = {
  find_cwe_by_id: tool({
    description: 'Look up a single CWE entry by numeric ID (e.g. "89"). Returns full detail including description. Use when you already know the CWE ID or to confirm a candidate from find_cwe_by_name.',
    inputSchema: findCweByIdSchema,
    execute: async ({ id }): Promise<{ id: string; name: string; description: string } | null> => {
      const list = await getCweList();
      const entry = list.find(c => c.ID === id);
      return entry ? { id: entry.ID, name: entry.Name, description: entry.Description } : null;
    },
  }),

  find_cwe_by_name: tool({
    description: 'Search CWEs by keyword in the name (e.g. "injection", "traversal", "race"). Returns id and name only for all matches — use find_cwe_by_id to get full details on a specific result.',
    inputSchema: findCweByNameSchema,
    execute: async ({ keyword }): Promise<Array<{ id: string; name: string }>> => {
      const list = await getCweList();
      return list
        .filter(c => c.Name.toLowerCase().includes(keyword.toLowerCase()))
        .slice(0, 20)
        .map(c => ({ id: c.ID, name: c.Name }));
    },
  }),

  find_cwe_by_capec: tool({
    description: 'Find CWEs mapped to a CAPEC attack pattern ID (e.g. "66"). Returns full detail. Use when reasoning from an attack vector rather than a weakness type.',
    inputSchema: findCweByCapecSchema,
    execute: async ({ capec_id }): Promise<Array<{ id: string; name: string; description: string }>> => {
      const list = await getCweList();
      return list
        .filter(c => c.CAPEC_IDs?.includes(capec_id))
        .map(c => ({ id: c.ID, name: c.Name, description: c.Description }));
    },
  }),
};
