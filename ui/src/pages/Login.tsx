import {
  ActionGroup,
  Alert,
  Bullseye,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  Content,
  ExpandableSection,
  Form,
  FormGroup,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Spinner,
  Tab,
  Tabs,
  TabTitleText,
  TextArea,
  TextInput,
} from "@patternfly/react-core";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api } from "../api";
import { ApiError } from "../api/client";
import type { AuthInfo, DeviceStart } from "../api/types";
import { useAuth } from "../auth";
import { Loading } from "../components/common";
import { useAsync } from "../hooks";

type Method = "password" | "sso" | "token";

export function Login() {
  const info = useAsync(() => api.authInfo(), []);
  const version = useAsync(() => api.version(), []);

  return (
    <Bullseye style={{ minHeight: "100vh", padding: 16 }}>
      <Card isLarge style={{ width: "min(32rem, 100%)" }}>
        <CardTitle>
          <Content component="h1">Sign in to silo</Content>
        </CardTitle>
        <CardBody>
          {info.error && (
            <Alert isInline variant="danger" title="Could not reach the server">
              {info.error.message}
            </Alert>
          )}
          {!info.data && !info.error && <Loading />}
          {info.data && <Methods info={info.data} />}
          {version.data && (
            <Content component="small" style={{ display: "block", marginTop: 24 }}>
              silo {version.data.version}
            </Content>
          )}
        </CardBody>
      </Card>
    </Bullseye>
  );
}

function Methods({ info }: { info: AuthInfo }) {
  const methods: Method[] = [];
  if (info.password_login_enabled) methods.push("password");
  if (info.oidc_enabled) methods.push("sso");
  methods.push("token");
  const [active, setActive] = useState<Method>(methods[0]!);

  return (
    <>
      <Tabs
        activeKey={active}
        onSelect={(_, key) => setActive(key as Method)}
        aria-label="Sign-in method"
        isFilled
      >
        {methods.includes("password") && (
          <Tab eventKey="password" title={<TabTitleText>Password</TabTitleText>} />
        )}
        {methods.includes("sso") && (
          <Tab eventKey="sso" title={<TabTitleText>Single sign-on</TabTitleText>} />
        )}
        <Tab eventKey="token" title={<TabTitleText>API token</TabTitleText>} />
      </Tabs>
      <div style={{ marginTop: 24 }}>
        {active === "password" && <PasswordForm />}
        {active === "sso" && <SsoForm info={info} />}
        {active === "token" && <TokenForm />}
      </div>
    </>
  );
}

function usePending() {
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setBusy(false);
    }
  };
  return { error, busy, run, setError, setBusy };
}

function PasswordForm() {
  const { signInWithSession } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { error, busy, run } = usePending();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => signInWithSession(await api.login(username, password)));
  };

  return (
    <Form onSubmit={submit}>
      {error && (
        <Alert isInline variant="danger" title="Sign-in failed">
          {error}
        </Alert>
      )}
      <FormGroup label="Username" isRequired fieldId="username">
        <TextInput
          id="username"
          value={username}
          onChange={(_, v) => setUsername(v)}
          autoComplete="username"
          autoFocus
          isRequired
        />
      </FormGroup>
      <FormGroup label="Password" isRequired fieldId="password">
        <TextInput
          id="password"
          type="password"
          value={password}
          onChange={(_, v) => setPassword(v)}
          autoComplete="current-password"
          isRequired
        />
      </FormGroup>
      <ActionGroup>
        <Button type="submit" variant="primary" isBlock isLoading={busy} isDisabled={busy}>
          Sign in
        </Button>
      </ActionGroup>
    </Form>
  );
}

function TokenForm() {
  const { signIn } = useAuth();
  const [token, setToken] = useState("");
  const { error, busy, run } = usePending();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(() => signIn(token.trim()));
  };

  return (
    <Form onSubmit={submit}>
      {error && (
        <Alert isInline variant="danger" title="That token was not accepted">
          {error}
        </Alert>
      )}
      <FormGroup label="API token" isRequired fieldId="api-token">
        <TextInput
          id="api-token"
          type="password"
          value={token}
          onChange={(_, v) => setToken(v)}
          autoComplete="off"
          isRequired
        />
        <FormHelperText>
          <HelperText>
            <HelperTextItem>
              The token printed at first start, or one made with <code>silo token create</code>.
              It stays in this tab and is cleared when the tab closes.
            </HelperTextItem>
          </HelperText>
        </FormHelperText>
      </FormGroup>
      <ActionGroup>
        <Button type="submit" variant="primary" isBlock isLoading={busy} isDisabled={busy || !token}>
          Use token
        </Button>
      </ActionGroup>
    </Form>
  );
}

type SsoState =
  | { phase: "idle" }
  | { phase: "starting" }
  | { phase: "waiting"; device: DeviceStart; deadline: number };

function SsoForm({ info }: { info: AuthInfo }) {
  const { signInWithSession } = useAuth();
  const [state, setState] = useState<SsoState>({ phase: "idle" });
  const [error, setError] = useState<string>();
  const cancelled = useRef(false);
  const [showToken, setShowToken] = useState(false);
  const [idToken, setIdToken] = useState("");
  const pasted = usePending();

  // Stop polling when the page is left.
  useEffect(
    () => () => {
      cancelled.current = true;
    },
    [],
  );

  const start = async () => {
    cancelled.current = false;
    setError(undefined);
    setState({ phase: "starting" });
    try {
      const device = await api.oidcDeviceStart();
      const deadline = Date.now() + device.expires_in * 1000;
      setState({ phase: "waiting", device, deadline });
      void poll(device, deadline);
    } catch (e) {
      setState({ phase: "idle" });
      setError(e instanceof ApiError ? e.message : String(e));
    }
  };

  const poll = async (device: DeviceStart, deadline: number) => {
    let interval = Math.max(device.interval, 1) * 1000;
    while (!cancelled.current) {
      await new Promise((resolve) => setTimeout(resolve, interval));
      if (cancelled.current) return;
      if (Date.now() >= deadline) {
        setState({ phase: "idle" });
        setError("The sign-in code expired before it was used. Start again.");
        return;
      }
      try {
        const result = await api.oidcDevicePoll(device.device_code);
        if (result.status === "ok") {
          cancelled.current = true;
          await signInWithSession(result.session);
          return;
        }
        // The provider asked for fewer requests: slow down, as it requires.
        if (result.status === "slow_down") interval += 5000;
      } catch (e) {
        setState({ phase: "idle" });
        setError(e instanceof ApiError ? e.message : String(e));
        return;
      }
    }
  };

  const cancel = () => {
    cancelled.current = true;
    setState({ phase: "idle" });
  };

  return (
    <>
      {error && (
        <Alert isInline variant="danger" title="Single sign-on failed" style={{ marginBottom: 16 }}>
          {error}
        </Alert>
      )}

      {state.phase !== "waiting" && (
        <>
          <Content component="p">
            Sign in with {info.oidc_issuer ? <strong>{info.oidc_issuer}</strong> : "your identity provider"}. You will
            approve the sign-in on the provider&apos;s page, then this one continues on its own.
          </Content>
          <Button
            variant="primary"
            isBlock
            onClick={start}
            isLoading={state.phase === "starting"}
            isDisabled={state.phase === "starting"}
            style={{ marginTop: 16 }}
          >
            Continue with single sign-on
          </Button>
        </>
      )}

      {state.phase === "waiting" && (
        <>
          <Content component="p">Open the provider&apos;s page to approve this sign-in:</Content>
          <Button
            component="a"
            variant="primary"
            isBlock
            href={state.device.verification_uri_complete ?? state.device.verification_uri}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open sign-in page
          </Button>
          {!state.device.verification_uri_complete && (
            <>
              <Content component="p" style={{ marginTop: 16 }}>
                Enter this code when asked:
              </Content>
              <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied">
                {state.device.user_code}
              </ClipboardCopy>
            </>
          )}
          <Content component="p" style={{ marginTop: 16 }}>
            <Spinner size="md" isInline /> Waiting for you to finish signing in…
          </Content>
          <Button variant="link" onClick={cancel}>
            Cancel
          </Button>
        </>
      )}

      <ExpandableSection
        toggleText="Have an ID token already?"
        isExpanded={showToken}
        onToggle={(_, expanded) => setShowToken(expanded)}
        style={{ marginTop: 24 }}
      >
        <Form
          onSubmit={(e) => {
            e.preventDefault();
            void pasted.run(async () => {
              const session = await api.loginOidc(idToken.trim());
              await signInWithSession(session);
            });
          }}
        >
          {pasted.error && (
            <Alert isInline variant="danger" title="That ID token was not accepted">
              {pasted.error}
            </Alert>
          )}
          <FormGroup label="OIDC ID token" fieldId="id-token">
            <TextArea
              id="id-token"
              value={idToken}
              onChange={(_, v) => setIdToken(v)}
              rows={3}
              resizeOrientation="vertical"
              autoComplete="off"
              spellCheck={false}
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  A token your CI system or identity provider minted. It is exchanged for a silo
                  session, like <code>silo login --oidc-token</code>.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <ActionGroup>
            <Button
              type="submit"
              variant="secondary"
              isLoading={pasted.busy}
              isDisabled={pasted.busy || !idToken.trim()}
            >
              Exchange token
            </Button>
          </ActionGroup>
        </Form>
      </ExpandableSection>
    </>
  );
}
