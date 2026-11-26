import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import openapi from '../src/docs/openapi.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const routeSources = [
  { prefix: '/auth', file: '../src/routes/auth.route.js' },
  { prefix: '/handoffs', file: '../src/routes/handoff.route.js' },
];
const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head']);
const failures = [];

const normalizePath = (value) => value.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
const routePaths = new Map();

for (const { prefix, file } of routeSources) {
  const source = fs.readFileSync(path.resolve(root, file), 'utf8');
  const pattern = /router\.(get|post|put|patch|delete|options|head)\(\s*['"]([^'"]+)['"]/g;
  for (const match of source.matchAll(pattern)) {
    const route = `${prefix}${match[2] === '/' ? '' : match[2]}`;
    routePaths.set(`${match[1].toUpperCase()} ${normalizePath(route)}`, true);
  }
}

const documented = new Map();
for (const [route, item] of Object.entries(openapi.paths || {})) {
  if (!route.startsWith('/auth/') && !route.startsWith('/handoffs')) failures.push(`Unsupported documented path: ${route}`);
  if (item.parameters?.some((parameter) => parameter.in === 'path' && !route.includes(`{${parameter.name}}`))) failures.push(`Path parameter is not present in path: ${route}`);
  for (const [method, operation] of Object.entries(item)) {
    if (!methods.has(method)) continue;
    const key = `${method.toUpperCase()} ${route}`;
    documented.set(key, true);
    if (!operation.operationId) failures.push(`Missing operationId: ${key}`);
    if (operation.responses && !Object.keys(operation.responses).length) failures.push(`Missing responses: ${key}`);
  }
}

for (const key of routePaths.keys()) if (!documented.has(key)) failures.push(`Route is undocumented: ${key}`);
for (const key of documented.keys()) if (!routePaths.has(key)) failures.push(`Documented operation is not an Express route: ${key}`);

const operationIds = new Set();
for (const item of Object.values(openapi.paths)) for (const [method, operation] of Object.entries(item)) {
  if (!methods.has(method)) continue;
  if (operationIds.has(operation.operationId)) failures.push(`Duplicate operationId: ${operation.operationId}`);
  operationIds.add(operation.operationId);
}

if (failures.length) {
  console.error(`OpenAPI contract validation failed (${failures.length} issue${failures.length === 1 ? '' : 's'}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`OpenAPI contract valid: ${documented.size} documented operations match the Express routes.`);
}
