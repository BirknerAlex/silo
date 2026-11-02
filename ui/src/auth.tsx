import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import { configureClient } from "./api/client";
import type { Session, WhoAmI } from "./api/types";

const STORAGE_KEY = "silo.token";

// sessionStorage, not localStorage: the credential should end with the tab,
// and it is only ever sent as a bearer header, never as a cookie.
function readStored(): string | null {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStored(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(STORAGE_KEY, token);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage can be unavailable (private mode); the session then lasts
    // until reload, which is the safe direction to fail in.
  }
}

/** What the signed-in credential is allowed to do, as far as the UI can tell. */
export interface Capabilities {
  /** Admin permission on at least some repos. */
  admin: boolean;
  /** Admin permission on every repo: users, stats, server settings. */
  globalAdmin: boolean;
}

export function capabilitiesOf(who: WhoAmI | undefined): Capabilities {
  const admin = who?.permission === "admin";
  return { admin, globalAdmin: admin && !!who?.all_repos };
}

interface AuthState {
  /** `undefined` while a stored credential is being checked. */
  ready: boolean;
  who: WhoAmI | undefined;
  capabilities: Capabilities;
  /** Accepts a token however it was obtained and loads who it belongs to. */
  signIn: (token: string) => Promise<void>;
  signInWithSession: (session: Session) => Promise<void>;
  signOut: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(readStored);
  const [who, setWho] = useState<WhoAmI>();
  const [ready, setReady] = useState(token === null);

  const signOut = useCallback(() => {
    writeStored(null);
    setToken(null);
    setWho(undefined);
    setReady(true);
  }, []);

  // The client reads the credential through a function so it always sees
  // the current one without being re-created.
  useEffect(() => {
    configureClient({ token: () => readStored(), unauthorized: signOut });
  }, [signOut]);

  const load = useCallback(
    async (candidate: string) => {
      writeStored(candidate);
      try {
        const me = await api.whoAmI();
        setToken(candidate);
        setWho(me);
      } catch (e) {
        writeStored(null);
        setToken(null);
        setWho(undefined);
        throw e;
      } finally {
        setReady(true);
      }
    },
    [],
  );

  useEffect(() => {
    if (token && !who) {
      load(token).catch(() => {
        /* the stored credential was refused: show the sign-in page */
      });
    }
    // Only on first load: later changes go through signIn.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      ready,
      who,
      capabilities: capabilitiesOf(who),
      signIn: load,
      signInWithSession: (session) => load(session.token),
      signOut,
    }),
    [ready, who, load, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}
