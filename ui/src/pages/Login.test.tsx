import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "../auth";
import { ToastProvider } from "../toast";
import { Login } from "./Login";

function serve(info: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const body = url.endsWith("GetAuthInfo")
        ? info
        : { version: "9.9.9", commit: "abc", built_at: "", formats: [] };
      return new Response(JSON.stringify(body), { status: 200 });
    }),
  );
}

function renderLogin() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <AuthProvider>
          <Login />
        </AuthProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("the sign-in page offers what the server accepts", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("password and API token when SSO is not configured", async () => {
    serve({ password_login_enabled: true, oidc_enabled: false });
    renderLogin();
    await screen.findByRole("tab", { name: "Password" });
    expect(screen.getByRole("tab", { name: "API token" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Single sign-on" })).not.toBeInTheDocument();
  });

  it("adds single sign-on when OIDC is configured", async () => {
    serve({ password_login_enabled: true, oidc_enabled: true, oidc_issuer: "https://id.example.com" });
    renderLogin();
    await screen.findByRole("tab", { name: "Single sign-on" });
    expect(screen.getByRole("tab", { name: "Password" })).toBeInTheDocument();
  });

  it("drops the password form when the server is SSO-only", async () => {
    serve({ password_login_enabled: false, oidc_enabled: true, oidc_issuer: "https://id.example.com" });
    renderLogin();
    await screen.findByRole("tab", { name: "Single sign-on" });
    expect(screen.queryByRole("tab", { name: "Password" })).not.toBeInTheDocument();
    // SSO is what is shown first, not a form that would be refused.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /continue with single sign-on/i })).toBeVisible(),
    );
  });

  it("shows why the server could not be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    renderLogin();
    await screen.findByText("Could not reach the server");
  });
});

describe("cancelling the single sign-on flow", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("is not undone by a poll that was already in flight", async () => {
    let releaseHeldPoll: () => void = () => {};
    let polls = 0;
    const calls: string[] = [];
    const device = {
      device_code: "d",
      user_code: "CODE-1",
      verification_uri: "https://id.example.com/verify",
      verification_uri_complete: null,
      expires_in: 60,
      interval: 1,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
        if (url.endsWith("GetAuthInfo"))
          return json({ password_login_enabled: false, oidc_enabled: true, oidc_issuer: "https://id" });
        if (url.endsWith("GetVersion")) return json({ version: "1", commit: "", built_at: "", formats: [] });
        if (url.endsWith("/oidc/device")) return json(device);
        if (url.endsWith("/oidc/token")) {
          polls += 1;
          // The first poll is held until after the person cancels and restarts;
          // later ones never finish, so only the stale one could sign in.
          await new Promise<void>((resolve) => {
            if (polls === 1) releaseHeldPoll = resolve;
          });
          return json({
            status: "ok",
            session: { token: "stale-token", username: "u", is_admin: false, expires_at: 0 },
          });
        }
        return json({});
      }),
    );

    renderLogin();
    fireEvent.click(await screen.findByRole("button", { name: /continue with single sign-on/i }));
    await waitFor(() => expect(polls).toBe(1), { timeout: 4000 });

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(await screen.findByRole("button", { name: /continue with single sign-on/i }));
    await screen.findByRole("button", { name: "Cancel" });

    releaseHeldPoll();
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(calls.some((u) => u.endsWith("WhoAmI"))).toBe(false);
  }, 15_000);
});
