// A thin client for the console's JSON gateway (`POST /admin/api/rpc/{Method}`).
// It holds no state of its own beyond where to find the current credential.

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

type TokenSource = () => string | null;
/** Called with the credential the server refused. */
type UnauthorizedHandler = (refused: string) => void;

let tokenSource: TokenSource = () => null;
let onUnauthorized: UnauthorizedHandler = () => {};

export function configureClient(options: {
  token: TokenSource;
  unauthorized: UnauthorizedHandler;
}): void {
  tokenSource = options.token;
  onUnauthorized = options.unauthorized;
}

// Where the gateway lives, relative to the origin. Overridable for tests.
export const API_ROOT = "/admin/api";

async function post<T>(path: string, body: unknown, sendToken: boolean): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = sendToken ? tokenSource() : null;
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let response: Response;
  try {
    response = await fetch(`${API_ROOT}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body ?? {}),
    });
  } catch {
    throw new ApiError("unavailable", "Could not reach the server.", 0);
  }

  const text = await response.text();
  let payload: unknown = undefined;
  try {
    payload = text ? JSON.parse(text) : undefined;
  } catch {
    // Fall through: a non-JSON body (a proxy's error page) is reported by status.
  }

  if (!response.ok) {
    const error = payload as { code?: string; message?: string } | undefined;
    const apiError = new ApiError(
      error?.code ?? "unknown",
      error?.message ?? `The server answered HTTP ${response.status}.`,
      response.status,
    );
    // A credential that was sent and refused means the session is over. A
    // failed sign-in also answers "unauthenticated", but sends no credential.
    if (token && apiError.code === "unauthenticated") onUnauthorized(token);
    throw apiError;
  }
  return payload as T;
}

/** Calls one gRPC method by name, e.g. `rpc("ListUsers")`. */
export function rpc<T>(method: string, body: object = {}): Promise<T> {
  return post<T>(`/rpc/${method}`, body, true);
}

/** A call made before there is a credential: sign-in and the OIDC relay. */
export function anonymous<T>(path: string, body: object = {}): Promise<T> {
  return post<T>(path, body, false);
}
