import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import { ApiError, configureClient } from "./api/client";
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

// The credential of the current session, kept in memory as well so a
// browser that refuses storage writes can still sign in for the life of the
// page. Set before `WhoAmI` is sent.
let sessionToken: string | null = null;

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

  // Each call to `load`, and each sign-out, is an attempt; only the latest
  // may change what is signed in. A slow answer for an earlier credential
  // (a second form submitted while the first request is pending, a restore
  // retry still waiting when the person signs out) must not replace, or sign
  // out, what came after it.
  const attempt = useRef(0);

  const signOut = useCallback(() => {
    attempt.current++;
    sessionToken = null;
    writeStored(null);
    setToken(null);
    setWho(undefined);
    setReady(true);
  }, []);

  // The client reads the credential through a function so it always sees
  // the current one without being re-created.
  useEffect(() => {
    configureClient({
      token: () => sessionToken ?? readStored(),
      // A late refusal of a credential that has since been replaced says
      // nothing about the current one.
      unauthorized: (refused) => {
        if (refused === (sessionToken ?? readStored())) signOut();
      },
    });
  }, [signOut]);

  // `restoring` is a stored credential being re-checked after a reload. It
  // is dropped only when the server refuses it: an outage or a proxy error
  // says nothing about whether it is still good.
  const load = useCallback(async (candidate: string, restoring = false) => {
    const mine = ++attempt.current;
    sessionToken = candidate;
    writeStored(candidate);
    try {
      const me = await api.whoAmI();
      if (mine !== attempt.current) return;
      setToken(candidate);
      setWho(me);
    } catch (e) {
      if (mine !== attempt.current) throw e;
      const refused = e instanceof ApiError && e.code === "unauthenticated";
      if (!restoring || refused) {
        sessionToken = null;
        writeStored(null);
        setToken(null);
      }
      setWho(undefined);
      throw e;
    } finally {
      if (mine === attempt.current) setReady(true);
    }
  }, []);

  useEffect(() => {
    if (token && !who) {
      // A refused credential is dropped and the sign-in page shows. Any
      // other failure (the server is restarting, a proxy answered 5xx) keeps
      // the credential, so try again a few times before giving up on it.
      const delays = [2000, 5000, 15000];
      let timer: ReturnType<typeof setTimeout> | undefined;
      const restore = (retriesLeft: number) => {
        const result = load(token, true);
        // `load` has already claimed its attempt number by the time it
        // returns, so this is the one that belongs to this try.
        const mine = attempt.current;
        result.catch((e: unknown) => {
          const refused = e instanceof ApiError && e.code === "unauthenticated";
          // Someone signed in or out since: this restore is superseded.
          if (refused || retriesLeft === 0 || attempt.current !== mine) return;
          timer = setTimeout(() => {
            if (attempt.current === mine) restore(retriesLeft - 1);
          }, delays[delays.length - retriesLeft]);
        });
      };
      restore(delays.length);
      return () => clearTimeout(timer);
    }
    // Only on first load: later changes go through signIn.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      ready,
      who,
      capabilities: capabilitiesOf(who),
      signIn: (candidate) => load(candidate),
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
