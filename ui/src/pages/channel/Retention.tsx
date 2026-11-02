import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  Content,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  HelperText,
  HelperTextItem,
  InputGroup,
  InputGroupItem,
  Label,
  LabelGroup,
  NumberInput,
  Switch,
  TextInput,
} from "@patternfly/react-core";
import { useEffect, useState, type FormEvent } from "react";
import { api } from "../../api";
import { OriginScope, type RunPruneResponse } from "../../api/types";
import { Loading, Query } from "../../components/common";
import { PruneResult } from "../../components/PruneResult";
import { Time } from "../../components/Time";
import { useAuth } from "../../auth";
import { useAsync } from "../../hooks";
import { useToast } from "../../toast";

export function Retention({ repo, channel }: { repo: string; channel: string }) {
  const rule = useAsync(() => api.getPruneRule(repo, channel), [repo, channel]);
  const exemptions = useAsync(() => api.listPruneExemptions(repo, channel), [repo, channel]);
  const info = useAsync(
    () => api.serverInfo().catch(() => undefined),
    [],
  );
  const { capabilities } = useAuth();

  return (
    <Grid hasGutter>
      {info.data && !info.data.prune_enabled && (
        <GridItem span={12}>
          <Alert isInline variant="warning" title="Pruning is switched off on this server">
            Rules can be saved, but nothing is deleted — neither on the schedule nor by “Run now” —
            until <code>prune.enabled</code> is set in the server configuration.
          </Alert>
        </GridItem>
      )}
      {!capabilities.globalAdmin && (
        <GridItem span={12}>
          <Content component="small">
            Whether pruning is enabled is a server setting; if “Run now” is refused, that is why.
          </Content>
        </GridItem>
      )}
      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Rule</CardTitle>
          <CardBody>
            <Query state={rule}>
              {(current) => (
                <RuleForm
                  repo={repo}
                  channel={channel}
                  rule={current}
                  onChanged={rule.reload}
                />
              )}
            </Query>
          </CardBody>
        </Card>
      </GridItem>
      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Exempt package names</CardTitle>
          <CardBody>
            <Query state={exemptions}>
              {(names) => (
                <Exemptions
                  repo={repo}
                  channel={channel}
                  names={names}
                  onChanged={exemptions.reload}
                />
              )}
            </Query>
          </CardBody>
        </Card>
      </GridItem>
      <GridItem span={12}>
        <RunNow repo={repo} channel={channel} />
      </GridItem>
    </Grid>
  );
}

function RuleForm({
  repo,
  channel,
  rule,
  onChanged,
}: {
  repo: string;
  channel: string;
  rule: { keep_last_n: number | null; max_age_days: number | null; origin_scope: number; updated_at: number } | null;
  onChanged: () => void;
}) {
  const toast = useToast();
  const [keepOn, setKeepOn] = useState(rule?.keep_last_n != null);
  const [keep, setKeep] = useState(rule?.keep_last_n ?? 5);
  const [ageOn, setAgeOn] = useState(rule?.max_age_days != null);
  const [age, setAge] = useState(rule?.max_age_days ?? 90);
  const [origin, setOrigin] = useState<number>(rule?.origin_scope || OriginScope.All);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setKeepOn(rule?.keep_last_n != null);
    setKeep(rule?.keep_last_n ?? 5);
    setAgeOn(rule?.max_age_days != null);
    setAge(rule?.max_age_days ?? 90);
    setOrigin(rule?.origin_scope || OriginScope.All);
  }, [rule]);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.setPruneRule({
        repo,
        channel,
        keep_last_n: keepOn ? keep : undefined,
        max_age_days: ageOn ? age : undefined,
        origin_scope: origin,
      });
      toast.success("Retention rule saved");
      onChanged();
    } catch (err) {
      toast.error("Could not save the rule", err);
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    setBusy(true);
    try {
      await api.clearPruneRule(repo, channel);
      toast.success("Retention rule cleared");
      onChanged();
    } catch (err) {
      toast.error("Could not clear the rule", err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Form onSubmit={save}>
      <Content component="small">
        {rule ? (
          <>
            Last changed <Time seconds={rule.updated_at} />. A version is pruned if it breaks
            either limit.
          </>
        ) : (
          "No rule is set: nothing in this channel is pruned automatically."
        )}
      </Content>
      <FormGroup fieldId="keep-on">
        <Switch
          id="keep-on"
          label="Keep only the newest N versions of each package"
          isChecked={keepOn}
          onChange={(_, v) => setKeepOn(v)}
        />
        {keepOn && (
          <NumberInput
            value={keep}
            min={1}
            onMinus={() => setKeep(Math.max(1, keep - 1))}
            onPlus={() => setKeep(keep + 1)}
            onChange={(e) => setKeep(Math.max(1, Number((e.target as HTMLInputElement).value) || 1))}
            inputAriaLabel="Versions to keep"
            style={{ marginTop: 8 }}
          />
        )}
      </FormGroup>
      <FormGroup fieldId="age-on">
        <Switch
          id="age-on"
          label="Delete versions published more than N days ago"
          isChecked={ageOn}
          onChange={(_, v) => setAgeOn(v)}
        />
        {ageOn && (
          <NumberInput
            value={age}
            min={1}
            onMinus={() => setAge(Math.max(1, age - 1))}
            onPlus={() => setAge(age + 1)}
            onChange={(e) => setAge(Math.max(1, Number((e.target as HTMLInputElement).value) || 1))}
            inputAriaLabel="Maximum age in days"
            style={{ marginTop: 8 }}
          />
        )}
      </FormGroup>
      <FormGroup label="Applies to" fieldId="origin">
        <FormSelect id="origin" value={origin} onChange={(_, v) => setOrigin(Number(v))}>
          <FormSelectOption value={OriginScope.All} label="All packages" />
          <FormSelectOption value={OriginScope.Local} label="Local only (published directly)" />
          <FormSelectOption value={OriginScope.Upstream} label="Upstream only (pulled through)" />
        </FormSelect>
      </FormGroup>
      <div style={{ display: "flex", gap: 8 }}>
        <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy || (!keepOn && !ageOn)}>
          Save rule
        </Button>
        {rule && (
          <Button variant="danger" isDisabled={busy} onClick={clear}>
            Clear rule
          </Button>
        )}
      </div>
      {!keepOn && !ageOn && (
        <FormHelperText>
          <HelperText>
            <HelperTextItem variant="warning">Turn on at least one limit to save a rule.</HelperTextItem>
          </HelperText>
        </FormHelperText>
      )}
    </Form>
  );
}

function Exemptions({
  repo,
  channel,
  names,
  onChanged,
}: {
  repo: string;
  channel: string;
  names: string[];
  onChanged: () => void;
}) {
  const toast = useToast();
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const set = async (target: string, exempt: boolean) => {
    setBusy(true);
    try {
      await api.setPruneExemption(repo, channel, target, exempt);
      toast.success(exempt ? `${target} is exempt from pruning` : `${target} can be pruned again`);
      setName("");
      onChanged();
    } catch (err) {
      toast.error("Could not change the exemption", err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Content component="p">
        Every version of an exempt package name is kept, whatever the rule says.
      </Content>
      {names.length === 0 ? (
        <Content component="small">No exemptions.</Content>
      ) : (
        <LabelGroup numLabels={20} aria-label="Exempt packages">
          {names.map((n) => (
            <Label key={n} onClose={() => void set(n, false)} closeBtnProps={{ isDisabled: busy }}>
              {n}
            </Label>
          ))}
        </LabelGroup>
      )}
      <Form
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) void set(name.trim(), true);
        }}
        style={{ marginTop: 16 }}
      >
        <InputGroup>
          <InputGroupItem isFill>
            <TextInput
              aria-label="Package name to exempt"
              placeholder="package name"
              value={name}
              onChange={(_, v) => setName(v)}
            />
          </InputGroupItem>
          <InputGroupItem>
            <Button type="submit" variant="control" isDisabled={busy || !name.trim()}>
              Exempt
            </Button>
          </InputGroupItem>
        </InputGroup>
      </Form>
    </>
  );
}

function RunNow({ repo, channel }: { repo: string; channel: string }) {
  const toast = useToast();
  const [busy, setBusy] = useState<"dry" | "real">();
  const [result, setResult] = useState<RunPruneResponse>();
  const [confirm, setConfirm] = useState(false);

  const run = async (dry: boolean) => {
    setBusy(dry ? "dry" : "real");
    // A preview of an earlier rule must not outlive the run that replaces it.
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
    <Card>
      <CardTitle>Run now</CardTitle>
      <CardBody>
        <Content component="p">
          Applies this channel&apos;s rule immediately, ignoring the schedule. Preview first.
        </Content>
        <div style={{ display: "flex", gap: 8 }}>
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
              <Button variant="link" onClick={() => setConfirm(false)} isDisabled={!!busy}>
                Cancel
              </Button>
            </>
          )}
        </div>
        {busy && !result && <Loading label="Pruning" />}
        {result && (
          <div style={{ marginTop: 16 }}>
            <PruneResult result={result} />
          </div>
        )}
      </CardBody>
    </Card>
  );
}
