import { render, screen, waitFor } from "@testing-library/react";
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
