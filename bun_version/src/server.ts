#!/usr/bin/env bun
import { searchVulns, serializeVulnsInResult, getVersion } from './core.ts';
import { loadConfig } from './utils/config.ts';
import type { Config } from './types/config.ts';

let config: Config;

/**
 * Initialize the server
 */
async function init() {
  config = await loadConfig();
  console.log('Loaded configuration');
}

/**
 * Handle CORS
 */
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

/**
 * API Server
 */
const server = Bun.serve({
  port: process.env.PORT || 5000,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    // Health check endpoint
    if (path === '/health' || path === '/') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          version: getVersion(),
          service: 'search_vulns_bun',
        }),
        {
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(),
          },
        }
      );
    }

    // Version endpoint
    if (path === '/api/version' || path === '/version') {
      return new Response(JSON.stringify({ version: getVersion() }), {
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(),
        },
      });
    }

    // Search endpoint
    if (path === '/api/search' || path === '/search') {
      try {
        let query: string | null = null;
        let ignoreGeneralProductVulns = false;
        let includeSingleVersionVulns = false;
        let includePatched = false;

        if (req.method === 'GET') {
          query = url.searchParams.get('q') || url.searchParams.get('query');
          ignoreGeneralProductVulns =
            url.searchParams.get('ignore_general_product_vulns') === 'true';
          includeSingleVersionVulns =
            url.searchParams.get('include_single_version_vulns') === 'true';
          includePatched = url.searchParams.get('include_patched') === 'true';
        } else if (req.method === 'POST') {
          const body = await req.json();
          query = body.query || body.q;
          ignoreGeneralProductVulns = body.ignore_general_product_vulns || false;
          includeSingleVersionVulns = body.include_single_version_vulns || false;
          includePatched = body.include_patched || false;
        }

        if (!query) {
          return new Response(
            JSON.stringify({
              error: 'Missing query parameter',
              message: 'Please provide a query parameter (q or query)',
            }),
            {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeaders(),
              },
            }
          );
        }

        // Perform search
        const result = await searchVulns(
          query,
          null,
          null,
          null,
          false,
          ignoreGeneralProductVulns,
          includeSingleVersionVulns,
          includePatched,
          config
        );

        // Serialize vulnerabilities
        serializeVulnsInResult(result);

        return new Response(JSON.stringify(result), {
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(),
          },
        });
      } catch (error) {
        console.error('Search error:', error);
        return new Response(
          JSON.stringify({
            error: 'Search failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          }),
          {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders(),
            },
          }
        );
      }
    }

    // Batch search endpoint
    if (path === '/api/batch-search' || path === '/batch-search') {
      try {
        if (req.method !== 'POST') {
          return new Response(
            JSON.stringify({
              error: 'Method not allowed',
              message: 'Only POST is supported for batch search',
            }),
            {
              status: 405,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeaders(),
              },
            }
          );
        }

        const body = await req.json();
        const queries = body.queries as string[];

        if (!queries || !Array.isArray(queries)) {
          return new Response(
            JSON.stringify({
              error: 'Invalid request',
              message: 'Please provide an array of queries',
            }),
            {
              status: 400,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeaders(),
              },
            }
          );
        }

        const ignoreGeneralProductVulns = body.ignore_general_product_vulns || false;
        const includeSingleVersionVulns = body.include_single_version_vulns || false;
        const includePatched = body.include_patched || false;

        const results: Record<string, any> = {};

        for (const query of queries) {
          try {
            const result = await searchVulns(
              query.trim(),
              null,
              null,
              null,
              false,
              ignoreGeneralProductVulns,
              includeSingleVersionVulns,
              includePatched,
              config
            );
            serializeVulnsInResult(result);
            results[query] = result;
          } catch (error) {
            results[query] = {
              error: error instanceof Error ? error.message : 'Unknown error',
            };
          }
        }

        return new Response(JSON.stringify(results), {
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders(),
          },
        });
      } catch (error) {
        console.error('Batch search error:', error);
        return new Response(
          JSON.stringify({
            error: 'Batch search failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          }),
          {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders(),
            },
          }
        );
      }
    }

    // 404 for unknown endpoints
    return new Response(
      JSON.stringify({
        error: 'Not found',
        message: `Endpoint ${path} not found`,
        available_endpoints: [
          '/',
          '/health',
          '/api/version',
          '/api/search',
          '/api/batch-search',
        ],
      }),
      {
        status: 404,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(),
        },
      }
    );
  },
});

// Initialize and start server
await init();

console.log(`🚀 Search Vulns API Server running on http://localhost:${server.port}`);
console.log(`
Available endpoints:
  GET  /                    - Health check
  GET  /health              - Health check
  GET  /api/version         - Get API version
  GET  /api/search?q=...    - Search for vulnerabilities
  POST /api/search          - Search for vulnerabilities (JSON body)
  POST /api/batch-search    - Batch search (JSON array of queries)

Example:
  curl "http://localhost:${server.port}/api/search?q=CVE-2024-27286"
  curl -X POST http://localhost:${server.port}/api/search -H "Content-Type: application/json" -d '{"query":"Sudo 1.8.2"}'
`);
