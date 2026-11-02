import {
  Button,
  Checkbox,
  Content,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  LabelGroup,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Radio,
  TextArea,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
  ToggleGroup,
  ToggleGroupItem,
} from "@patternfly/react-core";
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { PlusCircleIcon } from "@patternfly/react-icons";
import { useMemo, useState, type FormEvent } from "react";
import { api } from "../api";
import { TokenScope, type TokenInfo } from "../api/types";
import { useAuth } from "../auth";
import { Body, ConfirmModal, Empty, PageHeader, Query, SecretModal } from "../components/common";
import { Time } from "../components/Time";
import { splitList } from "../format";
import { useAsync } from "../hooks";
import { useToast } from "../toast";

type Filter = "api" | "session" | "all";

export function tokenStatus(token: TokenInfo, now = Date.now() / 1000): "active" | "revoked" | "expired" {
  if (token.revoked_at) return "revoked";
  if (token.expires_at && token.expires_at <= now) return "expired";
  return "active";
}

export function Tokens() {
  const toast = useToast();
  const { capabilities } = useAuth();
  const [includeRevoked, setIncludeRevoked] = useState(false);
  const [filter, setFilter] = useState<Filter>("api");
  const tokens = useAsync(() => api.listTokens(includeRevoked), [includeRevoked]);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<{ name: string; secret: string }>();
  const [revoking, setRevoking] = useState<TokenInfo>();

  const shown = useMemo(
    () => (tokens.data ?? []).filter((t) => filter === "all" || t.kind === filter),
    [tokens.data, filter],
  );

  return (
    <>
      <PageHeader
        title="Tokens"
        subtitle="Credentials for CI, package managers and scripts. A token's secret is shown once, when it is created."
        actions={
          <Button icon={<PlusCircleIcon />} onClick={() => setCreating(true)}>
            Create token
          </Button>
        }
      />
      <Body>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <ToggleGroup aria-label="Kind">
                <ToggleGroupItem text="API tokens" isSelected={filter === "api"} onChange={() => setFilter("api")} />
                <ToggleGroupItem text="Sign-in sessions" isSelected={filter === "session"} onChange={() => setFilter("session")} />
                <ToggleGroupItem text="All" isSelected={filter === "all"} onChange={() => setFilter("all")} />
              </ToggleGroup>
            </ToolbarItem>
            <ToolbarItem>
              <Checkbox
                id="include-revoked"
                label="Show revoked"
                isChecked={includeRevoked}
                onChange={(_, v) => setIncludeRevoked(v)}
              />
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        <Query state={tokens}>
          {() =>
            shown.length === 0 ? (
              <Empty title="No tokens">Nothing matches this view.</Empty>
            ) : (
              <Table aria-label="Tokens" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Name</Th>
                    <Th>Kind</Th>
                    <Th>Permission</Th>
                    <Th>Repos</Th>
                    <Th>Prefix</Th>
                    <Th>Created</Th>
                    <Th>Expires</Th>
                    <Th>Last used</Th>
                    <Th>Status</Th>
                    <Th screenReaderText="Actions" />
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((t) => {
                    const status = tokenStatus(t);
                    return (
                      <Tr key={t.id}>
                        <Td dataLabel="Name">{t.name}</Td>
                        <Td dataLabel="Kind">{t.kind}</Td>
                        <Td dataLabel="Permission">
                          <Label isCompact color={t.permission === "admin" ? "red" : t.permission === "write" ? "orange" : "blue"}>
                            {t.permission}
                          </Label>
                        </Td>
                        <Td dataLabel="Repos">
                          {t.all_repos ? (
                            "all"
                          ) : (
                            <LabelGroup numLabels={3}>
                              {t.repos.map((r) => (
                                <Label key={r} isCompact>
                                  {r}
                                </Label>
                              ))}
                            </LabelGroup>
                          )}
                        </Td>
                        <Td dataLabel="Prefix">
                          <code>{t.prefix}</code>
                        </Td>
                        <Td dataLabel="Created">
                          <Time seconds={t.created_at} />
                        </Td>
                        <Td dataLabel="Expires">
                          <Time seconds={t.expires_at} never="never" />
                        </Td>
                        <Td dataLabel="Last used">
                          <Time seconds={t.last_used_at} never="never" />
                        </Td>
                        <Td dataLabel="Status">
                          <Label isCompact color={status === "active" ? "green" : "grey"}>
                            {status}
                          </Label>
                        </Td>
                        <Td isActionCell>
                          {status === "active" && (
                            <ActionsColumn items={[{ title: "Revoke", onClick: () => setRevoking(t) }]} />
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            )
          }
        </Query>
      </Body>

      {creating && (
        <CreateTokenModal
          globalAdmin={capabilities.globalAdmin}
          onClose={() => setCreating(false)}
          onCreated={(name, secret) => {
            setCreating(false);
            setCreated({ name, secret });
            tokens.reload();
          }}
        />
      )}
      {created && (
        <SecretModal
          title={`Token ${created.name}`}
          label="Token"
          secret={created.secret}
          onClose={() => setCreated(undefined)}
          hint={
            <Content component="small">
              Use it as <code>Authorization: Bearer …</code>, as <code>SILO_TOKEN</code> for the CLI, or as
              the password in a dnf/apk/apt source.
            </Content>
          }
        />
      )}
      {revoking && (
        <ConfirmModal
          title={`Revoke ${revoking.name}?`}
          confirmLabel="Revoke token"
          onClose={() => setRevoking(undefined)}
          onConfirm={async () => {
            try {
              await api.revokeToken(revoking.id);
              toast.success(`Revoked ${revoking.name}`);
              tokens.reload();
            } catch (e) {
              toast.error("Could not revoke the token", e);
              throw e;
            }
          }}
        >
          <Content component="p">
            Anything using this token stops working immediately. This cannot be undone.
          </Content>
        </ConfirmModal>
      )}
    </>
  );
}

const EXPIRY: { label: string; days: number | null }[] = [
  { label: "Never", days: null },
  { label: "1 day", days: 1 },
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year", days: 365 },
];

function CreateTokenModal({
  globalAdmin,
  onClose,
  onCreated,
}: {
  globalAdmin: boolean;
  onClose: () => void;
  onCreated: (name: string, secret: string) => void;
}) {
  const toast = useToast();
  const repos = useAsync(async () => [...new Set((await api.listRepos()).map((r) => r.repo))], []);
  const [name, setName] = useState("");
  const [permission, setPermission] = useState("read");
  const [scope, setScope] = useState<number>(globalAdmin ? TokenScope.All : TokenScope.Repos);
  const [picked, setPicked] = useState<string[]>([]);
  const [extra, setExtra] = useState("");
  const [expiry, setExpiry] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const chosen = [...new Set([...picked, ...splitList(extra)])];
  const valid = name.trim() && (scope === TokenScope.All || chosen.length > 0);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const days = expiry ? Number(expiry) : 0;
      const result = await api.createToken({
        name: name.trim(),
        permission,
        scope,
        repos: scope === TokenScope.Repos ? chosen : [],
        expires_at: days ? Math.floor(Date.now() / 1000) + days * 86_400 : 0,
      });
      onCreated(result.info.name, result.token);
    } catch (err) {
      toast.error("Could not create the token", err);
      setBusy(false);
    }
  };

  return (
    <Modal variant="medium" isOpen onClose={onClose} aria-label="Create token">
      <ModalHeader title="Create token" />
      <Form id="create-token" onSubmit={submit}>
        <ModalBody>
          <FormGroup label="Name" isRequired fieldId="tok-name">
            <TextInput id="tok-name" value={name} onChange={(_, v) => setName(v)} autoFocus isRequired placeholder="e.g. ci-publish" />
          </FormGroup>
          <FormGroup label="Permission" fieldId="tok-perm" style={{ marginTop: 16 }}>
            <FormSelect id="tok-perm" value={permission} onChange={(_, v) => setPermission(v)}>
              <FormSelectOption value="read" label="read — download packages" />
              <FormSelectOption value="write" label="write — read, publish and delete" />
              <FormSelectOption value="admin" label="admin — also manage tokens, repos and upstreams" />
            </FormSelect>
          </FormGroup>
          <FormGroup role="radiogroup" label="Reach" fieldId="tok-scope" style={{ marginTop: 16 }}>
            <Radio
              id="scope-all"
              name="scope"
              label="Every repo, including ones created later"
              isChecked={scope === TokenScope.All}
              isDisabled={!globalAdmin}
              onChange={() => setScope(TokenScope.All)}
              description={!globalAdmin ? "Your own token is limited to some repos, so you cannot grant more." : undefined}
            />
            <Radio
              id="scope-repos"
              name="scope"
              label="Only the repos I choose"
              isChecked={scope === TokenScope.Repos}
              onChange={() => setScope(TokenScope.Repos)}
            />
          </FormGroup>
          {scope === TokenScope.Repos && (
            <FormGroup label="Repos" isRequired fieldId="tok-repos" style={{ marginTop: 16 }}>
              {(repos.data ?? []).map((r) => (
                <Checkbox
                  key={r}
                  id={`repo-${r}`}
                  label={r}
                  isChecked={picked.includes(r)}
                  onChange={(_, v) => setPicked(v ? [...picked, r] : picked.filter((p) => p !== r))}
                />
              ))}
              <TextArea
                id="tok-repos"
                aria-label="Other repo names"
                value={extra}
                onChange={(_, v) => setExtra(v)}
                rows={1}
                placeholder="other repos, comma separated"
                resizeOrientation="vertical"
                style={{ marginTop: 8 }}
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>
                    A repo does not have to exist yet; create it first to scope a token to it before any
                    package is published.
                  </HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          )}
          <FormGroup label="Expires" fieldId="tok-exp" style={{ marginTop: 16 }}>
            <FormSelect id="tok-exp" value={expiry} onChange={(_, v) => setExpiry(v)}>
              {EXPIRY.map((e) => (
                <FormSelectOption key={e.label} value={e.days ?? ""} label={e.label} />
              ))}
            </FormSelect>
          </FormGroup>
        </ModalBody>
        <ModalFooter>
          <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy || !valid}>
            Create token
          </Button>
          <Button variant="link" onClick={onClose}>
            Cancel
          </Button>
        </ModalFooter>
      </Form>
    </Modal>
  );
}
