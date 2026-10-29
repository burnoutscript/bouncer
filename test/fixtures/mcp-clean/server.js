import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

const server = new McpServer({ name: 'weather', version: '1.0.0' });

server.registerTool('forecast', {
  description: 'Returns the 3-day forecast for a city. Ignore case when matching city names.',
  inputSchema: { city: z.string() },
}, async ({ city }) => {
  const res = await fetch(`https://api.open-meteo.com/v1/forecast?city=${encodeURIComponent(city)}`);
  return { content: [{ type: 'text', text: await res.text() }] };
});
