/**
 * Single source of truth for frontend types.
 *
 * All non-Trident types AND the former `trident.ts` types now live together in
 * `agent-manager.ts`. Import everything from `@/types` (this barrel).
 */
export * from './agent-manager';
