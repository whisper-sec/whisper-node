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
export function verify(address: string, opts?: { timeout?: number }): Promise<boolean>;
export function ip(opts?: { timeout?: number }): Promise<string>;
export function firstAddr(obj: unknown): string | null;
