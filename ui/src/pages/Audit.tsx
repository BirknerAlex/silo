import {
  Button,
  Checkbox,
  CodeBlock,
  CodeBlockCode,
  FormSelect,
  FormSelectOption,
  Label,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { ExpandableRowContent, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { SyncAltIcon } from "@patternfly/react-icons";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import type { AuditEntry } from "../api/types";
import { Body, Empty, PageHeader, Query } from "../components/common";
import { formatTime } from "../format";
import { useAsync, useDebounced, useInterval } from "../hooks";

// The actions silo records; see `silo_db::audit::action`.
const ACTIONS = [
  "package.publish",
  "package.download",
  "package.delete",
  "index.regenerate",
  "repo.create",
  "repo.set_mode",
  "repo.delete",
  "repo.prune_run",
  "prune.rule_set",
  "prune.rule_clear",
  "prune.exemption_set",
  "token.create",
  "token.revoke",
  "user.create",
  "user.disable",
  "user.delete",
  "auth.login",
  "auth.failed",
  "upstream.add",
  "upstream.update",
  "upstream.remove",
  "upstream.sync",
  "object.gc",
  "server.bootstrap",
];

function prettyDetail(detail: string): string {
  try {
    return JSON.stringify(JSON.parse(detail), null, 2);
  } catch {
    return detail;
  }
}

export function Audit() {
  const [params, setParams] = useSearchParams();
  const action = params.get("action") ?? "";
  const [repo, setRepo] = useState(params.get("repo") ?? "");
  const [actor, setActor] = useState(params.get("actor") ?? "");
  const [failures, setFailures] = useState(false);
  const [limit, setLimit] = useState(100);
  const [live, setLive] = useState(false);
  const [open, setOpen] = useState<Set<number>>(new Set());

  const debouncedRepo = useDebounced(repo);
  const debouncedActor = useDebounced(actor);

  // Keep the URL in step with the typed filters, so a reload or a shared
  // link shows what is on screen. `action` is written by its own selector.
  useEffect(() => {
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        const set = (key: string, value: string) =>
          value.trim() ? next.set(key, value.trim()) : next.delete(key);
        set("repo", debouncedRepo);
        set("actor", debouncedActor);
        return next.toString() === previous.toString() ? previous : next;
      },
      { replace: true },
    );
  }, [debouncedRepo, debouncedActor, setParams]);

  const entries = useAsync(
    () =>
      api.queryAudit({
        action: action || undefined,
        repo: debouncedRepo.trim() || undefined,
        actor: debouncedActor.trim() || undefined,
        only_failures: failures,
        limit,
      }),
    [action, debouncedRepo, debouncedActor, failures, limit],
  );
  useInterval(entries.reload, 10_000, live);

  const toggle = (id: number) => {
    const next = new Set(open);
    if (!next.delete(id)) next.add(id);
    setOpen(next);
  };

  const download = (rows: AuditEntry[]) => {
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "silo-audit.json";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Every change, and every authenticated download while audit.log_downloads is on, newest first. Entries older than the retention period are pruned."
      />
      <Body>
        <Toolbar>
          <ToolbarContent>
            <ToolbarItem>
              <FormSelect
                aria-label="Action"
                value={action}
                onChange={(_, v) =>
                  setParams(
                    (previous) => {
                      const next = new URLSearchParams(previous);
                      if (v) next.set("action", v);
                      else next.delete("action");
                      return next;
                    },
                    { replace: true },
                  )
                }
              >
                <FormSelectOption value="" label="All actions" />
                {ACTIONS.map((a) => (
                  <FormSelectOption key={a} value={a} label={a} />
                ))}
                {action && !ACTIONS.includes(action) && <FormSelectOption value={action} label={action} />}
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>
              <TextInput aria-label="Repo" placeholder="Repo" value={repo} onChange={(_, v) => setRepo(v)} />
            </ToolbarItem>
            <ToolbarItem>
              <TextInput aria-label="Actor" placeholder="Actor" value={actor} onChange={(_, v) => setActor(v)} />
            </ToolbarItem>
            <ToolbarItem>
              <Checkbox id="only-failures" label="Rejected only" isChecked={failures} onChange={(_, v) => setFailures(v)} />
            </ToolbarItem>
            <ToolbarItem>
              <FormSelect aria-label="Rows" value={limit} onChange={(_, v) => setLimit(Number(v))}>
                {[50, 100, 250, 500, 1000].map((n) => (
                  <FormSelectOption key={n} value={n} label={`${n} rows`} />
                ))}
              </FormSelect>
            </ToolbarItem>
            <ToolbarItem>
              <Checkbox id="live" label="Live" isChecked={live} onChange={(_, v) => setLive(v)} />
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="plain" aria-label="Refresh" onClick={entries.reload}>
                <SyncAltIcon />
              </Button>
            </ToolbarItem>
            <ToolbarItem>
              <Button variant="secondary" isDisabled={!entries.data?.length} onClick={() => download(entries.data ?? [])}>
                Download JSON
              </Button>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
        <Query state={entries}>
          {(rows) =>
            rows.length === 0 ? (
              <Empty title="No matching entries" />
            ) : (
              <Table aria-label="Audit log" variant="compact">
                <Thead>
                  <Tr>
                    <Th screenReaderText="Expand" />
                    <Th>Time</Th>
                    <Th>Action</Th>
                    <Th>Actor</Th>
                    <Th>Repo / channel</Th>
                    <Th>Target</Th>
                    <Th>Result</Th>
                    <Th>From</Th>
                  </Tr>
                </Thead>
                {rows.map((e, index) => (
                  <Tbody key={e.id} isExpanded={open.has(e.id)}>
                    <Tr>
                      <Td expand={{ rowIndex: index, isExpanded: open.has(e.id), onToggle: () => toggle(e.id) }} />
                      <Td dataLabel="Time">{formatTime(e.at)}</Td>
                      <Td dataLabel="Action">
                        <code>{e.action}</code>
                      </Td>
                      <Td dataLabel="Actor">
                        {e.actor_name || "—"} <small>({e.actor_kind})</small>
                      </Td>
                      <Td dataLabel="Repo / channel">{e.repo ? `${e.repo}${e.channel ? `/${e.channel}` : ""}` : "—"}</Td>
                      <Td dataLabel="Target" modifier="breakWord">
                        {e.target || "—"}
                      </Td>
                      <Td dataLabel="Result">
                        <Label isCompact color={e.success ? "green" : "red"}>
                          {e.success ? "ok" : "rejected"}
                        </Label>
                      </Td>
                      <Td dataLabel="From">{e.remote_addr || "—"}</Td>
                    </Tr>
                    <Tr isExpanded={open.has(e.id)}>
                      <Td colSpan={8}>
                        <ExpandableRowContent>
                          <CodeBlock>
                            <CodeBlockCode>{prettyDetail(e.detail)}</CodeBlockCode>
                          </CodeBlock>
                        </ExpandableRowContent>
                      </Td>
                    </Tr>
                  </Tbody>
                ))}
              </Table>
            )
          }
        </Query>
      </Body>
    </>
  );
}
