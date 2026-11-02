import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, anonymous, configureClient, rpc } from "./client";

function respond(status: number, body: unknown) {
  return vi.fn().mockResolvedValue(
    new Response(typeof body === "string" ? body : JSON.stringify(body), { status }),
  );
}

describe("the gateway client", () => {
  const unauthorized = vi.fn();

  beforeEach(() => {
    unauthorized.mockReset();
    configureClient({ token: () => "secret-token", unauthorized });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("posts JSON with the bearer token", async () => {
    const fetchMock = respond(200, { users: [] });
    vi.stubGlobal("fetch", fetchMock);

    await expect(rpc("ListUsers", { a: 1 })).resolves.toEqual({ users: [] });

    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/admin/api/rpc/ListUsers");
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe("Bearer secret-token");
    expect(JSON.parse(init.body)).toEqual({ a: 1 });
  });

  it("sends no credential for sign-in calls", async () => {
    const fetchMock = respond(200, {});
    vi.stubGlobal("fetch", fetchMock);
    await anonymous("/rpc/Login", { username: "a", password: "b" });
    expect(fetchMock.mock.calls[0]![1].headers.Authorization).toBeUndefined();
  });

  it("turns an error body into an ApiError", async () => {
    vi.stubGlobal("fetch", respond(403, { code: "permission_denied", message: "nope" }));
    const error = await rpc("ListUsers").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: "permission_denied", message: "nope", status: 403 });
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it("ends the session when a sent credential is refused", async () => {
    vi.stubGlobal("fetch", respond(401, { code: "unauthenticated", message: "expired" }));
    await rpc("ListUsers").catch(() => {});
    expect(unauthorized).toHaveBeenCalledOnce();
  });

  it("does not end the session over a failed sign-in", async () => {
    vi.stubGlobal("fetch", respond(401, { code: "unauthenticated", message: "invalid" }));
    await anonymous("/rpc/Login", {}).catch(() => {});
    expect(unauthorized).not.toHaveBeenCalled();
  });

  it("reports a non-JSON failure by its status", async () => {
    vi.stubGlobal("fetch", respond(502, "<html>bad gateway</html>"));
    const error = await rpc("ListUsers").catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 502 });
    expect((error as ApiError).message).toContain("502");
  });

  it("reports an unreachable server", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("failed")));
    const error = await rpc("ListUsers").catch((e: unknown) => e);
    expect(error).toMatchObject({ code: "unavailable", status: 0 });
  });
});
