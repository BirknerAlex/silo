import { describe, expect, it } from "vitest";
import type { RepoInfo } from "../api/types";
import { summarize } from "./Repos";
import { tokenStatus } from "./Tokens";
import type { TokenInfo } from "../api/types";

const row = (over: Partial<RepoInfo>): RepoInfo => ({
  repo: "r",
  channel: "stable",
  format: 1,
  package_count: 1,
  total_bytes: 100,
  mode: 1,
  ...over,
});

describe("summarize", () => {
  it("folds repo/channel/format rows into one row per repo", () => {
    const [a, b] = summarize([
      row({ repo: "b", channel: "stable", format: 1, package_count: 2, total_bytes: 200 }),
      row({ repo: "a", channel: "stable", format: 1 }),
      row({ repo: "a", channel: "stable", format: 3, package_count: 4, total_bytes: 50 }),
      row({ repo: "a", channel: "edge", format: 1 }),
    ]);
    expect(a).toMatchObject({ repo: "a", channels: ["stable", "edge"], formats: [1, 3], packages: 6, bytes: 250 });
    expect(b).toMatchObject({ repo: "b", packages: 2 });
  });

  it("lists a repo that has no packages yet", () => {
    const [empty] = summarize([row({ repo: "new", channel: "", format: 0, package_count: 0, total_bytes: 0 })]);
    expect(empty).toMatchObject({ repo: "new", channels: [], formats: [], packages: 0 });
  });
});

describe("tokenStatus", () => {
  const token = (over: Partial<TokenInfo>): TokenInfo => ({
    id: "1",
    name: "t",
    prefix: "p",
    permission: "read",
    all_repos: true,
    repos: [],
    created_at: 0,
    expires_at: 0,
    last_used_at: 0,
    revoked_at: 0,
    kind: "api",
    ...over,
  });

  it("distinguishes active, revoked and expired", () => {
    expect(tokenStatus(token({}), 1000)).toBe("active");
    expect(tokenStatus(token({ expires_at: 2000 }), 1000)).toBe("active");
    expect(tokenStatus(token({ expires_at: 500 }), 1000)).toBe("expired");
    expect(tokenStatus(token({ revoked_at: 10, expires_at: 500 }), 1000)).toBe("revoked");
  });
});
