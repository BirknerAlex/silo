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
  SearchInput,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { PlusCircleIcon } from "@patternfly/react-icons";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { RepoMode, type RepoInfo } from "../api/types";
import { useAuth } from "../auth";
import {
  Body,
  ConfirmModal,
  Empty,
  FormatLabel,
  ModeLabel,
  PageHeader,
  Query,
} from "../components/common";
import { formatBytes, formatNumber } from "../format";
import { useAsync } from "../hooks";
import { useToast } from "../toast";

export interface RepoSummary {
  repo: string;
  mode: number;
  channels: string[];
  formats: number[];
  packages: number;
  bytes: number;
}

/** `ListRepos` returns one row per repo/channel/format; the console wants one per repo. */
export function summarize(rows: RepoInfo[]): RepoSummary[] {
  const byRepo = new Map<string, RepoSummary>();
  for (const row of rows) {
    let summary = byRepo.get(row.repo);
    if (!summary) {
      summary = { repo: row.repo, mode: row.mode, channels: [], formats: [], packages: 0, bytes: 0 };
      byRepo.set(row.repo, summary);
    }
    // A repo created ahead of its first publish has no channel yet.
    if (row.channel && !summary.channels.includes(row.channel)) summary.channels.push(row.channel);
    if (row.format && !summary.formats.includes(row.format)) summary.formats.push(row.format);
    summary.packages += row.package_count;
    summary.bytes += row.total_bytes;
  }
  return [...byRepo.values()].sort((a, b) => a.repo.localeCompare(b.repo));
}

export function Repos() {
  const { capabilities } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const repos = useAsync(async () => summarize(await api.listRepos()), []);
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const [toggling, setToggling] = useState<RepoSummary>();
  const [deleting, setDeleting] = useState<RepoSummary>();

  return (
    <>
      <PageHeader
        title="Repositories"
        subtitle="Each repo holds channels, and each channel holds packages of one or more formats."
        actions={
          capabilities.admin && (
            <Button icon={<PlusCircleIcon />} onClick={() => setCreating(true)}>
              Create repo
            </Button>
          )
        }
      />
      <Body>
        <Query state={repos}>
          {(all) => (
            <RepoTable
              all={all}
              search={search}
              onSearch={setSearch}
              canAdmin={capabilities.admin}
              onOpen={(repo) => navigate(`/repos/${encodeURIComponent(repo)}`)}
              onToggle={setToggling}
              onDelete={setDeleting}
              onCreate={() => setCreating(true)}
            />
          )}
        </Query>
      </Body>

      {creating && (
        <CreateRepoModal
          onClose={() => setCreating(false)}
          onCreated={(repo) => {
            setCreating(false);
            toast.success(`Created repo ${repo}`);
            repos.reload();
          }}
        />
      )}
      {toggling && (
        <ModeModal
          repo={toggling}
          onClose={() => setToggling(undefined)}
          onDone={() => {
            setToggling(undefined);
            repos.reload();
          }}
        />
      )}
      {deleting && (
        <DeleteRepoModal
          repo={deleting}
          onClose={() => setDeleting(undefined)}
          onDone={() => {
            setDeleting(undefined);
            repos.reload();
          }}
        />
      )}
    </>
  );
}

function RepoTable({
  all,
  search,
  onSearch,
  canAdmin,
  onOpen,
  onToggle,
  onDelete,
  onCreate,
}: {
  all: RepoSummary[];
  search: string;
  onSearch: (value: string) => void;
  canAdmin: boolean;
  onOpen: (repo: string) => void;
  onToggle: (repo: RepoSummary) => void;
  onDelete: (repo: RepoSummary) => void;
  onCreate: () => void;
}) {
  const rows = useMemo(
    () => all.filter((r) => r.repo.toLowerCase().includes(search.trim().toLowerCase())),
    [all, search],
  );

  if (all.length === 0) {
    return (
      <Empty
        title="No repositories"
        action={
          canAdmin && (
            <Button variant="primary" onClick={onCreate}>
              Create repo
            </Button>
          )
        }
      >
        A repo is created by an admin here or by the first publish into it.
      </Empty>
    );
  }

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput
              placeholder="Filter by name"
              value={search}
              onChange={(_, v) => onSearch(v)}
              onClear={() => onSearch("")}
              aria-label="Filter repos"
            />
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <Table aria-label="Repositories" variant="compact">
        <Thead>
          <Tr>
            <Th>Repo</Th>
            <Th>Mode</Th>
            <Th>Channels</Th>
            <Th>Formats</Th>
            <Th modifier="fitContent">Packages</Th>
            <Th modifier="fitContent">Size</Th>
            {canAdmin && <Th screenReaderText="Actions" />}
          </Tr>
        </Thead>
        <Tbody>
          {rows.map((r) => (
            <Tr key={r.repo}>
              <Td dataLabel="Repo">
                <Link to={`/repos/${encodeURIComponent(r.repo)}`} onClick={(e) => { e.preventDefault(); onOpen(r.repo); }}>
                  {r.repo}
                </Link>
              </Td>
              <Td dataLabel="Mode">
                <ModeLabel mode={r.mode} />
              </Td>
              <Td dataLabel="Channels">
                <LabelGroup numLabels={4}>
                  {r.channels.map((c) => (
                    <Label
                      key={c}
                      isCompact
                      render={({ className, content }) => (
                        <Link
                          className={className}
                          to={`/repos/${encodeURIComponent(r.repo)}/${encodeURIComponent(c)}`}
                        >
                          {content}
                        </Link>
                      )}
                    >
                      {c}
                    </Label>
                  ))}
                </LabelGroup>
              </Td>
              <Td dataLabel="Formats">
                {r.formats.map((f) => (
                  <span key={f} style={{ marginRight: 4 }}>
                    <FormatLabel format={f} />
                  </span>
                ))}
              </Td>
              <Td dataLabel="Packages">{formatNumber(r.packages)}</Td>
              <Td dataLabel="Size" modifier="nowrap">{formatBytes(r.bytes)}</Td>
              {canAdmin && (
                <Td isActionCell>
                  <ActionsColumn
                    items={[
                      {
                        title: r.mode === RepoMode.Public ? "Make private" : "Make public",
                        onClick: () => onToggle(r),
                      },
                      { isSeparator: true },
                      { title: "Delete", onClick: () => onDelete(r) },
                    ]}
                  />
                </Td>
              )}
            </Tr>
          ))}
        </Tbody>
      </Table>
      {rows.length === 0 && <Empty title="No matching repositories" />}
    </>
  );
}

export function CreateRepoModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (repo: string) => void;
}) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [mode, setMode] = useState<number>(RepoMode.Private);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.createRepo(name.trim(), mode);
      onCreated(name.trim());
    } catch (err) {
      toast.error("Could not create the repo", err);
      setBusy(false);
    }
  };

  return (
    <Modal variant="small" isOpen onClose={onClose} aria-label="Create repo">
      <ModalHeader title="Create repo" />
      <Form id="create-repo" onSubmit={submit}>
        <ModalBody>
          <FormGroup label="Name" isRequired fieldId="repo-name">
            <TextInput
              id="repo-name"
              value={name}
              onChange={(_, v) => setName(v)}
              autoFocus
              isRequired
              placeholder="e.g. internal"
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  Letters, digits, <code>-</code>, <code>_</code> and <code>.</code>. The name{" "}
                  <code>admin</code> is reserved.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <FormGroup label="Mode" fieldId="repo-mode" style={{ marginTop: 16 }}>
            <FormSelect id="repo-mode" value={mode} onChange={(_, v) => setMode(Number(v))}>
              <FormSelectOption value={RepoMode.Private} label="Private — reads need a credential" />
              <FormSelectOption value={RepoMode.Public} label="Public — anyone can read" />
            </FormSelect>
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  Public only adds anonymous reads. It never changes who can write.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
        </ModalBody>
        <ModalFooter>
          <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy || !name.trim()}>
            Create
          </Button>
          <Button variant="link" onClick={onClose}>
            Cancel
          </Button>
        </ModalFooter>
      </Form>
    </Modal>
  );
}

export function ModeModal({
  repo,
  onClose,
  onDone,
}: {
  repo: { repo: string; mode: number };
  onClose: () => void;
  onDone: () => void;
}) {
  const toast = useToast();
  const makePublic = repo.mode !== RepoMode.Public;
  return (
    <ConfirmModal
      title={makePublic ? `Make ${repo.repo} public?` : `Make ${repo.repo} private?`}
      confirmLabel={makePublic ? "Make public" : "Make private"}
      danger={makePublic}
      onClose={onClose}
      onConfirm={async () => {
        try {
          await api.setRepoMode(repo.repo, makePublic ? RepoMode.Public : RepoMode.Private);
          toast.success(`${repo.repo} is now ${makePublic ? "public" : "private"}`);
          onDone();
        } catch (e) {
          toast.error("Could not change the mode", e);
          throw e;
        }
      }}
    >
      <Content component="p">
        {makePublic
          ? "Anyone who can reach this server will be able to download every package in this repo without a credential. Writes are unaffected."
          : "Downloads will require a credential again. No token is revoked or deleted."}
      </Content>
    </ConfirmModal>
  );
}

export function DeleteRepoModal({
  repo,
  onClose,
  onDone,
}: {
  repo: { repo: string; packages: number };
  onClose: () => void;
  onDone: () => void;
}) {
  const toast = useToast();
  const [force, setForce] = useState(false);
  return (
    <ConfirmModal
      title={`Delete ${repo.repo}?`}
      confirmLabel="Delete repo"
      confirmText={repo.repo}
      onClose={onClose}
      onConfirm={async () => {
        try {
          const result = await api.deleteRepo(repo.repo, force);
          toast.success(
            `Deleted ${repo.repo}`,
            result.packages_deleted ? `${result.packages_deleted} packages removed.` : undefined,
          );
          onDone();
        } catch (e) {
          toast.error("Could not delete the repo", e);
          throw e;
        }
      }}
      extra={
        repo.packages > 0 && (
          <Checkbox
            id="force-delete"
            style={{ marginTop: 16 }}
            label={`Also delete its ${formatNumber(repo.packages)} packages (all channels and formats)`}
            isChecked={force}
            onChange={(_, checked) => setForce(checked)}
          />
        )
      }
    >
      <Content component="p">
        {repo.packages > 0
          ? "This repo still has packages. Without the box below the delete is refused."
          : "This repo has no packages."}
      </Content>
    </ConfirmModal>
  );
}
