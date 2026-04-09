#!/usr/bin/env node
/**
 * MCP Schema Sanitizer Proxy
 *
 * Wraps an MCP server and strips oneOf/allOf/anyOf from tool inputSchema
 * before passing responses back to Claude Code. This fixes the Anthropic API
 * error: "input_schema does not support oneOf, allOf, or anyOf at the top level"
 *
 * Usage: node schema-sanitizer.js <command> [args...]
 * Example: node schema-sanitizer.js node ./node_modules/.bin/evm-mcp-server
 */

const { spawn } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: node schema-sanitizer.js <command> [args...]');
  process.exit(1);
}

let command = args[0];
let commandArgs = args.slice(1);

// On Windows, launching a .js file directly can invoke the shell file association
// instead of Node. If the target is a JS entrypoint, force execution via Node.
if (/\.(c?m?js)$/i.test(command)) {
  commandArgs = [command, ...commandArgs];
  command = process.execPath;
}

// Spawn the actual MCP server
const child = spawn(command, commandArgs, {
  stdio: ['pipe', 'pipe', 'inherit'],
  env: process.env,
  shell: false
});

// Buffer for incomplete messages from the child
let childBuf = '';

// Parse JSON-RPC messages from a stream using Content-Length framing
function processChildOutput(chunk) {
  childBuf += chunk;

  while (true) {
    const headerEnd = childBuf.indexOf('\r\n\r\n');
    if (headerEnd === -1) break;

    const header = childBuf.substring(0, headerEnd);
    const match = header.match(/Content-Length:\s*(\d+)/i);
    if (!match) {
      // Not a proper message, skip to next \r\n\r\n
      childBuf = childBuf.substring(headerEnd + 4);
      continue;
    }

    const contentLength = parseInt(match[1], 10);
    const bodyStart = headerEnd + 4;

    if (childBuf.length < bodyStart + contentLength) break; // incomplete

    const body = childBuf.substring(bodyStart, bodyStart + contentLength);
    childBuf = childBuf.substring(bodyStart + contentLength);

    try {
      const msg = JSON.parse(body);

      // Sanitize tools/list response
      if (msg.result && msg.result.tools && Array.isArray(msg.result.tools)) {
        msg.result.tools = msg.result.tools.map(tool => {
          if (tool.inputSchema) {
            tool.inputSchema = sanitizeSchema(tool.inputSchema);
          }
          return tool;
        });
      }

      const sanitized = JSON.stringify(msg);
      process.stdout.write(`Content-Length: ${Buffer.byteLength(sanitized)}\r\n\r\n${sanitized}`);
    } catch (e) {
      // Pass through unparseable messages
      process.stdout.write(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    }
  }
}

/**
 * Recursively strip oneOf/allOf/anyOf from a JSON Schema object.
 * Strategy:
 * - Top-level oneOf/anyOf: pick the first non-null variant
 * - Top-level allOf: merge all sub-schemas
 * - Property-level: same treatment recursively
 */
function sanitizeSchema(schema, defs) {
  if (!schema || typeof schema !== 'object') return schema;
  if (Array.isArray(schema)) return schema.map(s => sanitizeSchema(s, defs));

  // Resolve $ref references using $defs
  if (schema['$ref'] && defs) {
    const refPath = schema['$ref'].replace('#/$defs/', '');
    const resolved = defs[refPath];
    if (resolved) {
      return sanitizeSchema({ ...resolved }, defs);
    }
  }

  // Capture $defs from root schema for ref resolution
  const localDefs = schema['$defs'] || defs;

  const result = { ...schema };

  // Remove $defs from output (already inlined via $ref resolution)
  delete result['$defs'];

  // Handle top-level anyOf (from z.optional / z.union)
  if (result.anyOf) {
    const variants = result.anyOf.filter(v => v.type !== 'null' && v.type !== undefined || v.properties);
    if (variants.length === 1) {
      // Single non-null variant — unwrap it
      const unwrapped = sanitizeSchema(variants[0], localDefs);
      delete result.anyOf;
      Object.assign(result, unwrapped);
    } else if (variants.length > 1) {
      // Multiple variants — pick the object one if exists, otherwise first
      const objVariant = variants.find(v => v.type === 'object' || v.properties);
      const picked = sanitizeSchema(objVariant || variants[0], localDefs);
      delete result.anyOf;
      Object.assign(result, picked);
    } else {
      // All null variants — just make it any type
      delete result.anyOf;
    }
  }

  // Handle top-level oneOf (from z.discriminatedUnion)
  if (result.oneOf) {
    // Pick the first variant that looks like an object schema
    const objVariant = result.oneOf.find(v => v.type === 'object' || v.properties);
    if (objVariant) {
      const picked = sanitizeSchema(objVariant, localDefs);
      delete result.oneOf;
      Object.assign(result, picked);
    } else {
      const picked = sanitizeSchema(result.oneOf[0], localDefs);
      delete result.oneOf;
      Object.assign(result, picked);
    }
  }

  // Handle top-level allOf (from z.intersection)
  if (result.allOf) {
    delete result.allOf;
    for (const sub of schema.allOf) {
      const sanitized = sanitizeSchema(sub, localDefs);
      // Merge properties
      if (sanitized.properties) {
        result.properties = { ...(result.properties || {}), ...sanitized.properties };
      }
      if (sanitized.required) {
        result.required = [...new Set([...(result.required || []), ...sanitized.required])];
      }
      if (sanitized.type && !result.type) {
        result.type = sanitized.type;
      }
    }
  }

  // Recurse into properties
  if (result.properties) {
    for (const [key, value] of Object.entries(result.properties)) {
      result.properties[key] = sanitizeSchema(value, localDefs);
    }
  }

  // Recurse into items (arrays)
  if (result.items) {
    result.items = sanitizeSchema(result.items, localDefs);
  }

  // Recurse into additionalProperties
  if (result.additionalProperties && typeof result.additionalProperties === 'object') {
    result.additionalProperties = sanitizeSchema(result.additionalProperties, localDefs);
  }

  return result;
}

// Pipe stdin to child (pass-through, no modification needed for requests)
process.stdin.pipe(child.stdin);

// Process child stdout through sanitizer
child.stdout.on('data', processChildOutput);

child.on('close', (code) => process.exit(code || 0));
child.on('error', (err) => {
  console.error('Failed to start MCP server:', err.message);
  process.exit(1);
});

process.on('SIGTERM', () => child.kill());
process.on('SIGINT', () => child.kill());
