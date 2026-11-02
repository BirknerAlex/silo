import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Content,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
} from "@patternfly/react-core";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { RunPruneResponse } from "../api/types";
import { useAuth } from "../auth";
import { Body, PageHeader, Query } from "../components/common";
import { PruneResult } from "../components/PruneResult";
import { useAsync } from "../hooks";
import { useToast } from "../toast";

/** Runs pruning outside the schedule, for everything or for one repo/channel. */
export function Prune() {
  const toast = useToast();
  const { capabilities } = useAuth();
  const repos = useAsync(() => api.listRepos(), []);
  const info = useAsync(() => api.serverInfo().catch(() => undefined), []);
  const [scope, setScope] = useState("");
  const [busy, setBusy] = useState<"dry" | "real">();
  const [confirm, setConfirm] = useState(false);
  const [result, setResult] = useState<RunPruneResponse>();

  const targets = useMemo(() => {
    const seen = new Set<string>();
    for (const r of repos.data ?? []) {
      if (r.channel) seen.add(`${r.repo}/${r.channel}`);
    }
    return [...seen].sort();
  }, [repos.data]);

  const run = async (dry: boolean) => {
    const [repo = "", channel = ""] = scope ? scope.split("/") : [];
    setBusy(dry ? "dry" : "real");
    setResult(undefined);
    try {
      setResult(await api.runPrune(repo, channel, dry));
    } catch (e) {
      toast.error("Prune failed", e);
    } finally {
      setBusy(undefined);
      setConfirm(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Retention"
        subtitle="Run pruning now, ignoring the schedule. Rules and exemptions are set per channel, on its Retention tab."
      />
      <Body>
        <Grid hasGutter>
          {info.data && !info.data.prune_enabled && (
            <GridItem span={12}>
              <Alert isInline variant="warning" title="Pruning is switched off on this server">
                Set <code>prune.enabled</code> in the server configuration for either the schedule or
                this page to delete anything.
              </Alert>
            </GridItem>
          )}
          {info.data && info.data.prune_enabled && (
            <GridItem span={12}>
              <Content component="small">
                Scheduled run:{" "}
                {info.data.jobs.find((j) => j.name === "package_prune")?.enabled
                  ? `on (${info.data.jobs.find((j) => j.name === "package_prune")?.schedule})`
                  : "off — only runs started here or with `silo prune`"}
              </Content>
            </GridItem>
          )}
          <GridItem span={12}>
            <Card>
              <CardTitle>Run pruning</CardTitle>
              <CardBody>
                <Query state={repos}>
                  {() => (
                    <Form isHorizontal style={{ maxWidth: 560 }}>
                      <FormGroup label="Scope" fieldId="prune-scope">
                        <FormSelect id="prune-scope" value={scope} onChange={(_, v) => setScope(v)}>
                          <FormSelectOption value="" label="Every configured rule" />
                          {targets.map((t) => (
                            <FormSelectOption key={t} value={t} label={t} />
                          ))}
                        </FormSelect>
                      </FormGroup>
                    </Form>
                  )}
                </Query>
                <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
                  <Button variant="secondary" onClick={() => void run(true)} isLoading={busy === "dry"} isDisabled={!!busy}>
                    Preview (dry run)
                  </Button>
                  {!confirm ? (
                    <Button variant="danger" onClick={() => setConfirm(true)} isDisabled={!!busy}>
                      Prune now…
                    </Button>
                  ) : (
                    <>
                      <Button variant="danger" onClick={() => void run(false)} isLoading={busy === "real"} isDisabled={!!busy}>
                        Yes, delete packages
                      </Button>
                      <Button variant="link" onClick={() => setConfirm(false)}>
                        Cancel
                      </Button>
                    </>
                  )}
                </div>
                {result && (
                  <div style={{ marginTop: 16 }}>
                    <PruneResult result={result} />
                  </div>
                )}
                <Content component="small" style={{ display: "block", marginTop: 16 }}>
                  Only channels with packages are listed. To configure a rule, open a channel from{" "}
                  <Link to="/repos">Repositories</Link>.
                </Content>
                {!capabilities.globalAdmin && (
                  <Content component="small">
                    With a repo-scoped token, “every configured rule” covers just your repos.
                  </Content>
                )}
              </CardBody>
            </Card>
          </GridItem>
        </Grid>
      </Body>
    </>
  );
}
