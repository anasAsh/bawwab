const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const token = process.env.GITHUB_TOKEN;
const server = new McpServer({ name: 'issues', version: '1.0.0' });
server.tool('list_issues', 'List open issues in a GitHub repository.', {}, async ({ owner, repo }) => {
  const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' },
  });
  return { content: [{ type: 'text', text: await r.text() }] };
});
