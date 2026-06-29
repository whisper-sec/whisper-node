// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
export declare class WhisperError extends Error {}

export interface Agent {
  /** The routable IPv6 /128 — both the identity and the auth. */
  address: string;
  id: string | null;
  name: string;
}

export interface Egress {
  port: number;
  address: string | null;
  proxyUrl: string;
  socksUrl: string;
  proxies: { http: string; https: string };
  /** Restore the proxy environment variables to their prior values. */
  close(): void;
}

export interface RegisterOptions { newKey?: boolean; timeout?: number; }
export interface EgressOptions { agent?: string; tier?: string; setEnv?: boolean; timeout?: number; }

export function register(name: string, opts?: RegisterOptions): Promise<Agent>;
export function egress(opts?: EgressOptions): Promise<Egress>;
export function withEgress<T>(fn: (e: Egress) => Promise<T> | T): Promise<T>;
export function withEgress<T>(opts: EgressOptions, fn: (e: Egress) => Promise<T> | T): Promise<T>;
/** Full server-side verify verdict (keyless). */
export interface VerifyVerdict {
  is_whisper_agent: boolean;
  fqdn?: string;
  operator?: string;
  tenant?: string;
  dane_ok?: boolean;
  jws_ok?: boolean;
  verified_at?: number;
  evidence?: unknown;
  [k: string]: unknown;
}

/** Keyless, CLI-free: is `address` a real Whisper agent? (server-side DANE+DNSSEC+reverse-DNS+JWS) */
export function verify(address: string, opts?: { timeout?: number }): Promise<boolean>;
/** Keyless, CLI-free: the full verify verdict, or null if not an agent. */
export function verifyDetails(address: string, opts?: { timeout?: number }): Promise<VerifyVerdict | null>;
/** Keyless, CLI-free: the public RDAP record for a /128, or null. */
export function rdap(address: string, opts?: { timeout?: number }): Promise<Record<string, unknown> | null>;
/** Keyless, CLI-free: the caller's current egress IP (what this process leaves from). */
export function egressIp(opts?: { timeout?: number }): Promise<string>;
/** Your current egress IP via the CLI (proves your /128). */
export function ip(opts?: { timeout?: number }): Promise<string>;
export function firstAddr(obj: unknown): string | null;
