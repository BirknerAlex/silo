import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  ClipboardCopy,
  Content,
  Form,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Label,
  SearchInput,
  Tab,
  Tabs,
  TabTitleText,
  TextInput,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { ActionsColumn, Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useMemo, useState, type FormEvent } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { PackageFormat, type PackageInfo } from "../api/types";
import { useAuth } from "../auth";
import {
  Body,
  ConfirmModal,
  Empty,
  FormatLabel,
  PageHeader,
  Query,
} from "../components/common";
import { Time } from "../components/Time";
import { FORMATS, formatBytes, formatName, formatNumber, packageVersion } from "../format";
import { useAsync } from "../hooks";
import { useToast } from "../toast";
import { Retention } from "./channel/Retention";
import { Upstreams } from "./channel/Upstreams";

type TabKey = "packages" | "upstreams" | "retention" | "index";

export function Channel() {
  const { repo = "", channel = "" } = useParams();
  const { capabilities } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabKey | null) ?? "packages";
  const select = (key: TabKey) => setParams(key === "packages" ? {} : { tab: key }, { replace: true });

  return (
    <>
      <PageHeader
        title={`${repo} / ${channel}`}
        breadcrumb={
          <Breadcrumb style={{ marginBottom: 8 }}>
            <BreadcrumbItem to="/admin/repos" onClick={(e) => { e.preventDefault(); navigate("/repos"); }}>
              Repositories
            </BreadcrumbItem>
            <BreadcrumbItem
              to={`/admin/repos/${encodeURIComponent(repo)}`}
              onClick={(e) => {
                e.preventDefault();
                navigate(`/repos/${encodeURIComponent(repo)}`);
              }}
            >
              {repo}
            </BreadcrumbItem>
            <BreadcrumbItem isActive>{channel}</BreadcrumbItem>
          </Breadcrumb>
        }
      />
      <Body>
        <Tabs activeKey={tab} onSelect={(_, key) => select(key as TabKey)} aria-label="Channel" mountOnEnter unmountOnExit>
          <Tab eventKey="packages" title={<TabTitleText>Packages</TabTitleText>}>
            <div style={{ paddingTop: 16 }}>
              <Packages repo={repo} channel={channel} canAdmin={capabilities.admin} />
            </div>
          </Tab>
          {capabilities.admin && (
            <Tab eventKey="upstreams" title={<TabTitleText>Upstreams</TabTitleText>}>
              <div style={{ paddingTop: 16 }}>
                <Upstreams repo={repo} channel={channel} />
              </div>
            </Tab>
          )}
          {capabilities.admin && (
            <Tab eventKey="retention" title={<TabTitleText>Retention</TabTitleText>}>
              <div style={{ paddingTop: 16 }}>
                <Retention repo={repo} channel={channel} />
              </div>
            </Tab>
          )}
          {capabilities.admin && (
            <Tab eventKey="index" title={<TabTitleText>Index</TabTitleText>}>
              <div style={{ paddingTop: 16 }}>
                <RebuildIndex repo={repo} channel={channel} />
              </div>
            </Tab>
          )}
        </Tabs>
      </Body>
    </>
  );
}

function Packages({ repo, channel, canAdmin }: { repo: string; channel: string; canAdmin: boolean }) {
  const toast = useToast();
  const [format, setFormat] = useState<number>(PackageFormat.Unspecified);
  const [search, setSearch] = useState("");
  const [deleting, setDeleting] = useState<PackageInfo>();
  const packages = useAsync(() => api.listPackages(repo, channel, format), [repo, channel, format]);

  const filter = search.trim().toLowerCase();
  const shown = useMemo(
    () =>
      (packages.data ?? []).filter(
        (p) =>
          !filter ||
          p.name.toLowerCase().includes(filter) ||
          p.version.toLowerCase().includes(filter) ||
          p.sha256.startsWith(filter),
      ),
    [packages.data, filter],
  );

  return (
    <>
      <Toolbar>
        <ToolbarContent>
          <ToolbarItem>
            <SearchInput
              placeholder="Filter by name, version or checksum"
              value={search}
              onChange={(_, v) => setSearch(v)}
              onClear={() => setSearch("")}
              aria-label="Filter packages"
              style={{ minWidth: 280 }}
            />
          </ToolbarItem>
          <ToolbarItem>
            <FormSelect
              aria-label="Format"
              value={format}
              onChange={(_, v) => setFormat(Number(v))}
            >
              <FormSelectOption value={PackageFormat.Unspecified} label="All formats" />
              {FORMATS.map((f) => (
                <FormSelectOption key={f.value} value={f.value} label={f.name} />
              ))}
            </FormSelect>
          </ToolbarItem>
          <ToolbarItem>
            <Button variant="secondary" onClick={packages.reload}>
              Refresh
            </Button>
          </ToolbarItem>
        </ToolbarContent>
      </Toolbar>
      <Query state={packages}>
        {(all) =>
          all.length === 0 ? (
            <Empty title="No packages">Nothing is published to this channel yet.</Empty>
          ) : (
            <>
              <Table aria-label="Packages" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Name</Th>
                    <Th>Version</Th>
                    <Th>Format</Th>
                    <Th>Arch</Th>
                    <Th modifier="fitContent">Size</Th>
                    <Th>SHA-256</Th>
                    <Th>Published</Th>
                    <Th>Origin</Th>
                    <Th modifier="fitContent">ID</Th>
                    {canAdmin && <Th screenReaderText="Actions" />}
                  </Tr>
                </Thead>
                <Tbody>
                  {shown.map((p) => (
                    <Tr key={p.id}>
                      <Td dataLabel="Name">{p.name}</Td>
                      <Td dataLabel="Version">{packageVersion(p)}</Td>
                      <Td dataLabel="Format">
                        <FormatLabel format={p.format} />
                      </Td>
                      <Td dataLabel="Arch">{p.arch || "—"}</Td>
                      <Td dataLabel="Size" modifier="nowrap">{formatBytes(p.size_bytes)}</Td>
                      <Td dataLabel="SHA-256">
                        <code title={p.sha256}>{p.sha256.slice(0, 12)}</code>
                      </Td>
                      <Td dataLabel="Published">
                        <Time seconds={p.published_at} />
                      </Td>
                      <Td dataLabel="Origin">
                        {p.origin_upstream ? (
                          <Label isCompact variant="outline">
                            {p.origin_upstream}
                          </Label>
                        ) : (
                          "local"
                        )}
                      </Td>
                      <Td dataLabel="ID">{p.id}</Td>
                      {canAdmin && (
                        <Td isActionCell>
                          <ActionsColumn
                            items={[{ title: "Delete", onClick: () => setDeleting(p) }]}
                          />
                        </Td>
                      )}
                    </Tr>
                  ))}
                </Tbody>
              </Table>
              <Content component="small" style={{ display: "block", marginTop: 8 }}>
                {formatNumber(shown.length)} of {formatNumber(all.length)} packages
              </Content>
              {shown.length === 0 && <Empty title="No matching packages" />}
            </>
          )
        }
      </Query>
      {deleting && (
        <ConfirmModal
          title={`Delete ${deleting.name} ${packageVersion(deleting)}?`}
          confirmLabel="Delete package"
          onClose={() => setDeleting(undefined)}
          onConfirm={async () => {
            try {
              await api.deletePackage(deleting.id);
              toast.success(`Deleted ${deleting.name} ${packageVersion(deleting)}`);
              packages.reload();
            } catch (e) {
              toast.error("Could not delete the package", e);
              throw e;
            }
          }}
        >
          <Content component="p">
            The file is removed from storage and the {formatName(deleting.format)} index is
            regenerated. Clients that have it cached keep it; new installs will not find it.
          </Content>
          <ClipboardCopy isReadOnly variant="inline-compact">
            {deleting.storage_path}
          </ClipboardCopy>
        </ConfirmModal>
      )}
    </>
  );
}

function RebuildIndex({ repo, channel }: { repo: string; channel: string }) {
  const toast = useToast();
  const [format, setFormat] = useState<number>(PackageFormat.Rpm);
  const [group, setGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ objects: string[]; groups_rebuilt: number }>();

  const hint: Record<number, string> = {
    [PackageFormat.Rpm]: "RPM has one index per channel; leave empty.",
    [PackageFormat.Apk]: "An architecture, e.g. x86_64.",
    [PackageFormat.Npm]: "A package name, e.g. @acme/widget.",
    [PackageFormat.Pacman]: "An architecture, e.g. x86_64.",
    [PackageFormat.Deb]: "An architecture, e.g. amd64.",
    [PackageFormat.Flatpak]: "Flatpak remotes keep no rebuildable index.",
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setResult(undefined);
    try {
      const rebuilt = await api.rebuildIndex(repo, channel, format, group.trim());
      setResult(rebuilt);
      toast.success(`Rebuilt ${rebuilt.groups_rebuilt} index group${rebuilt.groups_rebuilt === 1 ? "" : "s"}`);
    } catch (err) {
      toast.error("Could not rebuild the index", err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card isPlain>
      <CardBody>
        <Content component="p">
          Regenerates an index from the database. Use it after restoring a bucket from backup, or to
          repair an index an interrupted publish left stale.
        </Content>
        <Form onSubmit={submit} style={{ maxWidth: 480 }}>
          <FormGroup label="Format" fieldId="index-format" isRequired>
            <FormSelect
              id="index-format"
              value={format}
              onChange={(_, v) => setFormat(Number(v))}
            >
              {FORMATS.map((f) => (
                <FormSelectOption key={f.value} value={f.value} label={f.name} />
              ))}
            </FormSelect>
          </FormGroup>
          <FormGroup label="Index group" fieldId="index-group">
            <TextInput id="index-group" value={group} onChange={(_, v) => setGroup(v)} />
            <FormHelperText>
              <HelperText>
                <HelperTextItem>
                  {hint[format]} Empty rebuilds every group of this format.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>
          <div>
            <Button type="submit" variant="primary" isLoading={busy} isDisabled={busy}>
              Rebuild index
            </Button>
          </div>
        </Form>
        {result && (
          <Alert
            isInline
            variant="success"
            title={`Rebuilt ${result.groups_rebuilt} group${result.groups_rebuilt === 1 ? "" : "s"}`}
            style={{ marginTop: 16 }}
          >
            {result.objects.length > 0 ? (
              <ul>
                {result.objects.map((o) => (
                  <li key={o}>
                    <code>{o}</code>
                  </li>
                ))}
              </ul>
            ) : (
              "No objects were rewritten."
            )}
          </Alert>
        )}
      </CardBody>
    </Card>
  );
}
