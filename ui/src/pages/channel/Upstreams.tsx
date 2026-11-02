import {
  Alert,
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
  Popover,
  Radio,
  Switch,
  TextArea,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { PlusCircleIcon } from "@patternfly/react-icons";
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useState, type FormEvent } from "react";
import { api } from "../../api";
import {
  CacheMode,
  PackageFormat,
  type AddUpstreamRequest,
  type UpdateUpstreamRequest,
  type UpstreamInfo,
} from "../../api/types";
import { ConfirmModal, Empty, FormatLabel, Query } from "../../components/common";
import { Time } from "../../components/Time";
import {
  UPSTREAM_FORMATS,
  cacheModeName,
  formatName,
  sameList,
  splitList,
} from "../../format";
import { useAsync } from "../../hooks";
import { useToast } from "../../toast";

const NEEDS_ARCHES = new Set<number>([PackageFormat.Apk, PackageFormat.Pacman, PackageFormat.Deb]);

export function Upstreams({ repo, channel }: { repo: string; channel: string }) {
  const toast = useToast();
  const upstreams = useAsync(() => api.listUpstreams(repo, channel), [repo, channel]);
  const info = useAsync(() => api.serverInfo().catch(() => undefined), []);
  const [editing, setEditing] = useState<UpstreamInfo | "new">();
  const [removing, setRemoving] = useState<UpstreamInfo>();
  const [syncing, setSyncing] = useState<string>();

  const sync = async (u: UpstreamInfo) => {
    setSyncing(u.name);
    try {
      const result = await api.syncUpstream(repo, channel, u.name);
      toast.success(`Synced ${u.name}`, `${result.packages_synced} packages indexed.`);
    } catch (e) {
      toast.error(`Could not sync ${u.name}`, e);
    } finally {
      setSyncing(undefined);
      upstreams.reload();
    }
  };

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <Button icon={<PlusCircleIcon />} onClick={() => setEditing("new")}>
              Add upstream
            </Button>
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <Content component="p">
        An upstream lets this channel answer for packages it does not hold, by pulling them through
        from another registry or mirror.
      </Content>
      <Query state={upstreams}>
        {(list) =>
          list.length === 0 ? (
            <Empty title="No upstreams">Add one to pull packages through from a mirror.</Empty>
          ) : (
            <Table aria-label="Upstreams" variant="compact">
              <Thead>
                <Tr>
                  <Th>Name</Th>
                  <Th>Format</Th>
                  <Th>URL</Th>
                  <Th>Status</Th>
                  <Th modifier="fitContent">Priority</Th>
                  <Th>Cache</Th>
                  <Th>Names</Th>
                  <Th>Last sync</Th>
                  <Th screenReaderText="Actions" />
                </Tr>
              </Thead>
              <Tbody>
                {list.map((u) => (
                  <Tr key={u.id}>
                    <Td dataLabel="Name">
                      {u.name} {u.auth_configured && <Label isCompact>auth</Label>}
                    </Td>
                    <Td dataLabel="Format">
                      <FormatLabel format={u.format} />
                    </Td>
                    <Td dataLabel="URL" modifier="breakWord">
                      {u.base_url}
                    </Td>
                    <Td dataLabel="Status">
                      <Status upstream={u} busy={syncing === u.name} />
                    </Td>
                    <Td dataLabel="Priority">{u.priority}</Td>
                    <Td dataLabel="Cache">{cacheModeName(u.cache_mode)}</Td>
                    <Td dataLabel="Names">
                      {u.package_patterns.length === 0 ? (
                        "all"
                      ) : (
                        <LabelGroup numLabels={3}>
                          {u.package_patterns.map((p) => (
                            <Label key={p} isCompact>
                              {p}
                            </Label>
                          ))}
                        </LabelGroup>
                      )}
                    </Td>
                    <Td dataLabel="Last sync">
                      <Time seconds={u.last_sync_at} never="never" />
                    </Td>
                    <Td isActionCell>
                      <ActionsColumn
                        items={[
                          { title: "Sync now", onClick: () => void sync(u) },
                          { title: "Edit", onClick: () => setEditing(u) },
                          { isSeparator: true },
                          { title: "Remove", onClick: () => setRemoving(u) },
                        ]}
                      />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )
        }
      </Query>

      {editing && (
        <UpstreamModal
          repo={repo}
          channel={channel}
          existing={editing === "new" ? undefined : editing}
          secretMissing={info.data ? !info.data.upstream_secret_configured : false}
          onClose={() => setEditing(undefined)}
          onSaved={() => {
            setEditing(undefined);
            upstreams.reload();
          }}
        />
      )}
      {removing && (
        <RemoveUpstream
          repo={repo}
          channel={channel}
          upstream={removing}
          onClose={() => setRemoving(undefined)}
          onDone={upstreams.reload}
        />
      )}
    </>
  );
}

function Status({ upstream, busy }: { upstream: UpstreamInfo; busy: boolean }) {
  if (busy) return <Label isCompact>syncing…</Label>;
  const color = upstream.status === "ok" ? "green" : upstream.status === "error" ? "red" : "grey";
  const label = (
    <Label isCompact color={color}>
      {upstream.status}
    </Label>
  );
  if (upstream.status !== "error" || !upstream.last_sync_error) return label;
  return (
    <Popover headerContent="Last sync failed" bodyContent={upstream.last_sync_error}>
      <span style={{ cursor: "pointer" }}>{label}</span>
    </Popover>
  );
}

type AuthChoice = "keep" | "none" | "basic" | "bearer";

function UpstreamModal({
  repo,
  channel,
  existing,
  secretMissing,
  onClose,
  onSaved,
}: {
  repo: string;
  channel: string;
  existing?: UpstreamInfo;
  secretMissing: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const editing = !!existing;
  const [name, setName] = useState(existing?.name ?? "");
  const [format, setFormat] = useState<number>(existing?.format ?? PackageFormat.Rpm);
  const [url, setUrl] = useState(existing?.base_url ?? "");
  const [cache, setCache] = useState<number>(existing?.cache_mode || CacheMode.Cache);
  const [indexInMemory, setIndexInMemory] = useState(existing?.cache_index_in_memory ?? false);
  const [priority, setPriority] = useState(String(existing?.priority ?? 0));
  const [patterns, setPatterns] = useState((existing?.package_patterns ?? []).join("\n"));
  const [arches, setArches] = useState((existing?.arches ?? []).join(", "));
  const [suite, setSuite] = useState(existing?.suite ?? "");
  const [components, setComponents] = useState((existing?.components ?? []).join(", "));
  const [auth, setAuth] = useState<AuthChoice>(existing?.auth_configured ? "keep" : "none");
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);

  const usesAuth = auth === "basic" || auth === "bearer";
  const isDeb = format === PackageFormat.Deb;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (existing) {
        const req: UpdateUpstreamRequest = { repo, channel, name: existing.name };
        if (url.trim() !== existing.base_url) req.base_url = url.trim();
        if (cache !== existing.cache_mode) req.cache_mode = cache;
        if (indexInMemory !== existing.cache_index_in_memory) req.cache_index_in_memory = indexInMemory;
        if (Number(priority) !== existing.priority) req.priority = Number(priority) || 0;

        const nextPatterns = splitList(patterns);
        if (!sameList(nextPatterns, existing.package_patterns)) {
          if (nextPatterns.length) req.package_patterns = nextPatterns;
          else req.clear_package_patterns = true;
        }
        if (NEEDS_ARCHES.has(existing.format)) {
          const next = splitList(arches);
          if (!sameList(next, existing.arches)) {
            if (next.length) req.arches = next;
            else req.clear_arches = true;
          }
        }
        if (isDeb) {
          if (suite.trim() !== existing.suite) req.suite = suite.trim();
          const next = splitList(components);
          if (!sameList(next, existing.components)) {
            if (next.length) req.components = next;
            else req.clear_components = true;
          }
        }
        if (auth === "none") req.auth = { kind: "", username: "", secret: "" };
        if (usesAuth) req.auth = { kind: auth, username: username.trim(), secret };
        await api.updateUpstream(req);
        toast.success(`Updated ${existing.name}`);
      } else {
        const req: AddUpstreamRequest = {
          repo,
          channel,
          name: name.trim(),
          format,
          base_url: url.trim(),
          cache_mode: cache,
          cache_index_in_memory: indexInMemory,
          arches: NEEDS_ARCHES.has(format) ? splitList(arches) : [],
          suite: isDeb ? suite.trim() : "",
          components: isDeb ? splitList(components) : [],
          priority: Number(priority) || 0,
          package_patterns: splitList(patterns),
        };
        if (usesAuth) req.auth = { kind: auth, username: username.trim(), secret };
        await api.addUpstream(req);
        toast.success(`Added ${name.trim()}`, "The first sync succeeded.");
      }
      onSaved();
    } catch (err) {
      toast.error(editing ? "Could not update the upstream" : "Could not add the upstream", err);
      setBusy(false);
    }
  };

  return (
    <Modal variant="medium" isOpen onClose={busy ? undefined : onClose} aria-label="Upstream">
      <ModalHeader title={editing ? `Edit ${existing.name}` : "Add upstream"} />
      <Form id="upstream-form" onSubmit={submit}>
        <ModalBody>
          {!editing && (
            <Alert isInline variant="info" title="The first sync runs now" style={{ marginBottom: 16 }}>
              The index is fetched before anything is saved. If it fails, nothing is created and the
              error is shown here. A large mirror can take a while.
            </Alert>
          )}
          <FormGroup label="Name" isRequired fieldId="up-name">
            <TextInput
              id="up-name"
              value={name}
              onChange={(_, v) => setName(v)}
              isDisabled={editing}
              isRequired
              placeholder="e.g. npmjs"
            />
          </FormGroup>
          <FormGroup label="Format" isRequired fieldId="up-format" style={{ marginTop: 16 }}>
            <FormSelect
              id="up-format"
              value={format}
              onChange={(_, v) => setFormat(Number(v))}
              isDisabled={editing}
            >
              {UPSTREAM_FORMATS.map((f) => (
                <FormSelectOption key={f.value} value={f.value} label={f.name} />
              ))}
            </FormSelect>
            {editing && (
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>
                    Name and format identify an upstream and cannot change; add a new one instead.
                  </HelperTextItem>
                </HelperText>
              </FormHelperText>
            )}
          </FormGroup>
          <FormGroup label="Base URL" isRequired fieldId="up-url" style={{ marginTop: 16 }}>
            <TextInput
              id="up-url"
              type="url"
              value={url}
              onChange={(_, v) => setUrl(v)}
              isRequired
              placeholder={format === PackageFormat.Npm ? "https://registry.npmjs.org" : "https://mirror.example.com/…"}
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  An absolute http(s) URL with no credentials in it; use the authentication section.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>

          <FormGroup role="radiogroup" label="Package files" fieldId="up-cache" style={{ marginTop: 16 }}>
            <Radio
              id="cache-yes"
              name="cache"
              label="Cache — store pulled-through files in silo's own storage"
              isChecked={cache === CacheMode.Cache}
              onChange={() => setCache(CacheMode.Cache)}
            />
            <Radio
              id="cache-no"
              name="cache"
              label="No cache — only redirect or proxy to the upstream"
              isChecked={cache === CacheMode.NoCache}
              onChange={() => setCache(CacheMode.NoCache)}
            />
          </FormGroup>
          <FormGroup fieldId="up-index-mem" style={{ marginTop: 16 }}>
            <Switch
              id="up-index-mem"
              label="Keep the synced index in memory for faster lookups"
              isChecked={indexInMemory}
              onChange={(_, v) => setIndexInMemory(v)}
            />
          </FormGroup>

          <FormGroup label="Priority" fieldId="up-priority" style={{ marginTop: 16 }}>
            <TextInput
              id="up-priority"
              type="number"
              value={priority}
              onChange={(_, v) => setPriority(v)}
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>Tried highest first; ties fall back to the name.</HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <FormGroup label="Only for package names matching" fieldId="up-patterns" style={{ marginTop: 16 }}>
            <TextArea
              id="up-patterns"
              value={patterns}
              onChange={(_, v) => setPatterns(v)}
              rows={2}
              placeholder="@acme/*"
              resizeOrientation="vertical"
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  Globs (<code>*</code>, <code>?</code>), one per line. Empty means this upstream
                  answers for every name. Use it when two upstreams are not interchangeable mirrors.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>

          {NEEDS_ARCHES.has(format) && (
            <FormGroup label="Architectures to sync" fieldId="up-arches" style={{ marginTop: 16 }}>
              <TextInput
                id="up-arches"
                value={arches}
                onChange={(_, v) => setArches(v)}
                placeholder={isDeb ? "amd64, arm64" : "x86_64, aarch64"}
              />
              <FormHelperText>
                <HelperText>
                  <HelperTextItem>Comma separated.</HelperTextItem>
                </HelperText>
              </FormHelperText>
            </FormGroup>
          )}
          {isDeb && (
            <>
              <FormGroup label="Suite" fieldId="up-suite" style={{ marginTop: 16 }}>
                <TextInput id="up-suite" value={suite} onChange={(_, v) => setSuite(v)} placeholder="bookworm" />
              </FormGroup>
              <FormGroup label="Components" fieldId="up-components" style={{ marginTop: 16 }}>
                <TextInput
                  id="up-components"
                  value={components}
                  onChange={(_, v) => setComponents(v)}
                  placeholder="main, contrib"
                />
              </FormGroup>
            </>
          )}

          <FormGroup role="radiogroup" label="Authentication to the upstream" fieldId="up-auth" style={{ marginTop: 16 }}>
            {editing && existing.auth_configured && (
              <Radio
                id="auth-keep"
                name="auth"
                label="Keep the stored credential"
                isChecked={auth === "keep"}
                onChange={() => setAuth("keep")}
              />
            )}
            <Radio
              id="auth-none"
              name="auth"
              label={editing && existing.auth_configured ? "Remove the stored credential" : "None"}
              isChecked={auth === "none"}
              onChange={() => setAuth("none")}
            />
            <Radio
              id="auth-basic"
              name="auth"
              label={editing && existing.auth_configured ? "Replace with a username and password" : "Username and password (basic)"}
              isChecked={auth === "basic"}
              onChange={() => setAuth("basic")}
            />
            <Radio
              id="auth-bearer"
              name="auth"
              label={editing && existing.auth_configured ? "Replace with a bearer token" : "Bearer token"}
              isChecked={auth === "bearer"}
              onChange={() => setAuth("bearer")}
            />
          </FormGroup>
          {usesAuth && (
            <>
              {secretMissing && (
                <Alert isInline variant="warning" title="No upstream secret key is configured" style={{ marginTop: 16 }}>
                  The server cannot store a credential until <code>upstream_secret.key</code> is set.
                  The Server page can generate one.
                </Alert>
              )}
              {auth === "basic" && (
                <FormGroup label="Username" isRequired fieldId="up-user" style={{ marginTop: 16 }}>
                  <TextInput
                    id="up-user"
                    value={username}
                    onChange={(_, v) => setUsername(v)}
                    autoComplete="off"
                    isRequired
                  />
                </FormGroup>
              )}
              <FormGroup
                label={auth === "basic" ? "Password" : "Token"}
                isRequired
                fieldId="up-secret"
                style={{ marginTop: 16 }}
              >
                <TextInput
                  id="up-secret"
                  type="password"
                  value={secret}
                  onChange={(_, v) => setSecret(v)}
                  autoComplete="off"
                  isRequired
                />
                <FormHelperText>
                  <HelperText>
                    <HelperTextItem>
                      Stored encrypted. It is never shown again, by this page or by the CLI.
                    </HelperTextItem>
                  </HelperText>
                </FormHelperText>
              </FormGroup>
            </>
          )}
        </ModalBody>
        <ModalFooter>
          <Button
            type="submit"
            variant="primary"
            isLoading={busy}
            isDisabled={busy || !url.trim() || (!editing && !name.trim())}
          >
            {editing ? "Save changes" : busy ? "Adding and syncing…" : "Add and sync"}
          </Button>
          <Button variant="link" onClick={onClose} isDisabled={busy}>
            Cancel
          </Button>
        </ModalFooter>
      </Form>
    </Modal>
  );
}

function RemoveUpstream({
  repo,
  channel,
  upstream,
  onClose,
  onDone,
}: {
  repo: string;
  channel: string;
  upstream: UpstreamInfo;
  onClose: () => void;
  onDone: () => void;
}) {
  const toast = useToast();
  const [prune, setPrune] = useState(false);
  return (
    <ConfirmModal
      title={`Remove ${upstream.name}?`}
      confirmLabel="Remove upstream"
      onClose={onClose}
      onConfirm={async () => {
        try {
          const result = await api.removeUpstream(repo, channel, upstream.name, prune);
          toast.success(
            `Removed ${upstream.name}`,
            prune ? `${result.packages_pruned} cached packages deleted.` : undefined,
          );
          onDone();
        } catch (e) {
          toast.error("Could not remove the upstream", e);
          throw e;
        }
      }}
      extra={
        <Checkbox
          id="prune-cached"
          style={{ marginTop: 16 }}
          label={`Also delete the ${formatName(upstream.format)} packages it cached`}
          isChecked={prune}
          onChange={(_, v) => setPrune(v)}
        />
      }
    >
      <Content component="p">
        Without the box below, packages already pulled through keep being served, relabelled as local.
      </Content>
    </ConfirmModal>
  );
}
