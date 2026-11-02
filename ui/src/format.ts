import { CacheMode, OriginScope, PackageFormat, RepoMode } from "./api/types";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value >= 100 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

/** Unix seconds to a local date and time; 0 means "not set". */
export function formatTime(seconds: number, fallback = "—"): string {
  if (!seconds) return fallback;
  return new Date(seconds * 1000).toLocaleString();
}

export function formatDay(seconds: number): string {
  return new Date(seconds * 1000).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
}

/** "3 minutes ago", "in 2 days". */
export function formatRelative(seconds: number, now = Date.now()): string {
  if (!seconds) return "—";
  const diff = seconds * 1000 - now;
  const abs = Math.abs(diff);
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
    ["second", 1000],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of units) {
    if (abs >= size || unit === "second") {
      return formatter.format(Math.round(diff / size), unit);
    }
  }
  return "—";
}

export function formatDuration(totalSeconds: number): string {
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${totalSeconds}s`;
}

const FORMAT_NAMES: Record<number, string> = {
  [PackageFormat.Rpm]: "rpm",
  [PackageFormat.Apk]: "apk",
  [PackageFormat.Npm]: "npm",
  [PackageFormat.Pacman]: "pacman",
  [PackageFormat.Deb]: "deb",
  [PackageFormat.Flatpak]: "flatpak",
};

export function formatName(format: number): string {
  return FORMAT_NAMES[format] ?? "";
}

export function parseFormat(name: string): number {
  const entry = Object.entries(FORMAT_NAMES).find(([, value]) => value === name);
  return entry ? Number(entry[0]) : PackageFormat.Unspecified;
}

/** Formats a user can publish or pull through: everything but "unspecified". */
export const FORMATS = Object.entries(FORMAT_NAMES).map(([value, name]) => ({
  value: Number(value),
  name,
}));

/** Formats an upstream can mirror. Flatpak remotes are published, not pulled through. */
export const UPSTREAM_FORMATS = FORMATS.filter((f) => f.value !== PackageFormat.Flatpak);

export function modeName(mode: number): string {
  return mode === RepoMode.Public ? "public" : "private";
}

export function originScopeName(scope: number): string {
  switch (scope) {
    case OriginScope.Local:
      return "local only";
    case OriginScope.Upstream:
      return "upstream only";
    default:
      return "all packages";
  }
}

export function cacheModeName(mode: number): string {
  return mode === CacheMode.NoCache ? "no cache" : "cache";
}

/** Splits a free-form list typed as lines or commas into trimmed, non-empty items. */
export function splitList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((item, i) => item === b[i]);
}

/** Version string as the CLI lists it: `[epoch:]version[-release]`. */
export function packageVersion(p: { version: string; release: string }): string {
  return p.release ? `${p.version}-${p.release}` : p.version;
}

/** 32 random bytes, base64: the key `upstream_secret.key` expects. */
export function generateUpstreamSecretKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}
