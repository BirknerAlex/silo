import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatDuration,
  generateUpstreamSecretKey,
  packageVersion,
  parseFormat,
  sameList,
  splitList,
} from "./format";

describe("formatBytes", () => {
  it("scales to the largest sensible binary unit", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GiB");
    expect(formatBytes(250 * 1024 ** 2)).toBe("250 MiB");
  });

  it("tolerates nonsense", () => {
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
  });
});

describe("formatDuration", () => {
  it("shows the two largest units", () => {
    expect(formatDuration(42)).toBe("42s");
    expect(formatDuration(125)).toBe("2m");
    expect(formatDuration(3 * 3600 + 5 * 60)).toBe("3h 5m");
    expect(formatDuration(2 * 86_400 + 4 * 3600)).toBe("2d 4h");
  });
});

describe("lists typed into a form", () => {
  it("splits on commas and newlines and drops blanks", () => {
    expect(splitList("amd64, arm64\n\n  riscv64 ,")).toEqual(["amd64", "arm64", "riscv64"]);
    expect(splitList("")).toEqual([]);
  });

  it("compares in order", () => {
    expect(sameList(["a", "b"], ["a", "b"])).toBe(true);
    expect(sameList(["a", "b"], ["b", "a"])).toBe(false);
    expect(sameList([], ["a"])).toBe(false);
  });
});

describe("package helpers", () => {
  it("shows the release only when there is one", () => {
    expect(packageVersion({ version: "1.2.3", release: "4" })).toBe("1.2.3-4");
    expect(packageVersion({ version: "1.2.3", release: "" })).toBe("1.2.3");
  });

  it("maps format names both ways", () => {
    expect(parseFormat("deb")).toBe(5);
    expect(parseFormat("nonsense")).toBe(0);
  });
});

describe("generateUpstreamSecretKey", () => {
  it("is 32 random bytes in base64", () => {
    const key = generateUpstreamSecretKey();
    expect(atob(key)).toHaveLength(32);
    expect(generateUpstreamSecretKey()).not.toBe(key);
  });
});
