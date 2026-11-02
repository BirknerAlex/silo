import {
  Card,
  CardBody,
  CardTitle,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Flex,
  FlexItem,
  Gallery,
  GalleryItem,
  Grid,
  GridItem,
  Label,
  Progress,
  ProgressMeasureLocation,
  ToggleGroup,
  ToggleGroupItem,
  Button,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { SyncAltIcon } from "@patternfly/react-icons";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Stats } from "../api/types";
import { ActivityChart, FormatDonut } from "../components/Charts";
import { Body, Empty, FormatLabel, ModeLabel, PageHeader, Query } from "../components/common";
import { Time } from "../components/Time";
import {
  formatBytes,
  formatDuration,
  formatName,
  formatNumber,
  formatTime,
  packageVersion,
} from "../format";
import { useAsync, useInterval } from "../hooks";

function Stat({
  title,
  value,
  detail,
  to,
}: {
  title: string;
  value: string;
  detail?: React.ReactNode;
  to?: string;
}) {
  return (
    <Card isCompact isFullHeight>
      <CardTitle>{to ? <Link to={to}>{title}</Link> : title}</CardTitle>
      <CardBody>
        <Content component="h2" style={{ fontSize: "2rem", margin: 0 }}>
          {value}
        </Content>
        {detail && (
          <Content component="small" style={{ display: "block" }}>
            {detail}
          </Content>
        )}
      </CardBody>
    </Card>
  );
}

export function Dashboard() {
  const [days, setDays] = useState(30);
  const stats = useAsync(() => api.stats(days), [days]);
  // The figures are cheap to compute and an operator watching a publish
  // land wants to see it.
  // Not while the tab is hidden: the figures are aggregates over the audit
  // log, and nobody is looking at them.
  useInterval(() => {
    if (!document.hidden) stats.reload();
  }, 30_000, true);
  // Catch up at once when the tab comes back, rather than at the next tick.
  useEffect(() => {
    const onVisible = () => {
      if (!document.hidden) stats.reload();
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
    // `reload` is stable; `stats` itself changes every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={
          stats.data ? `Updated ${formatTime(stats.data.generated_at)}` : "Registry usage and activity"
        }
        actions={
          <Flex spaceItems={{ default: "spaceItemsMd" }}>
            <FlexItem>
              <ToggleGroup aria-label="Window">
                {[7, 30, 90].map((d) => (
                  <ToggleGroupItem
                    key={d}
                    text={`${d} days`}
                    isSelected={days === d}
                    onChange={() => setDays(d)}
                  />
                ))}
              </ToggleGroup>
            </FlexItem>
            <FlexItem>
              <Button variant="plain" aria-label="Refresh" onClick={stats.reload}>
                <SyncAltIcon />
              </Button>
            </FlexItem>
          </Flex>
        }
      />
      <Body>
        <Query state={stats}>{(s) => <DashboardBody stats={s} days={days} />}</Query>
      </Body>
    </>
  );
}

function DashboardBody({ stats, days }: { stats: Stats; days: number }) {
  const t = stats.totals;
  const slices = stats.formats.map((f) => ({
    name: formatName(f.format) || "unknown",
    bytes: f.bytes,
    packages: f.packages,
  }));
  const maxRepoBytes = Math.max(1, ...stats.repos.map((r) => r.bytes));
  const up = stats.upstreams;
  const run = stats.runtime;
  const downloadsServed = run.downloads_proxy + run.downloads_redirect;

  return (
    <Grid hasGutter>
      <GridItem span={12}>
        <Gallery hasGutter minWidths={{ default: "170px" }}>
          <GalleryItem>
            <Stat
              title="Packages"
              value={formatNumber(t.packages)}
              detail={`${formatNumber(t.upstream_packages)} pulled through`}
            />
          </GalleryItem>
          <GalleryItem>
            <Stat title="Storage" value={formatBytes(t.bytes)} detail="across all repos" />
          </GalleryItem>
          <GalleryItem>
            <Stat
              title="Repositories"
              to="/repos"
              value={formatNumber(t.repos)}
              detail={`${formatNumber(t.channels)} channels · ${formatNumber(t.public_repos)} public`}
            />
          </GalleryItem>
          <GalleryItem>
            <Stat
              title="Users"
              to="/users"
              value={formatNumber(t.users)}
              detail={`${formatNumber(t.admin_users)} admin · ${formatNumber(t.disabled_users)} disabled · ${formatNumber(t.oidc_users)} SSO`}
            />
          </GalleryItem>
          <GalleryItem>
            <Stat
              title="API tokens"
              to="/tokens"
              value={formatNumber(t.api_tokens)}
              detail={`${formatNumber(t.session_tokens)} sessions · ${formatNumber(t.revoked_tokens)} revoked · ${formatNumber(t.expired_tokens)} expired`}
            />
          </GalleryItem>
          <GalleryItem>
            <Stat
              title="Upstreams"
              value={formatNumber(up.total)}
              detail={
                up.total === 0 ? (
                  "none configured"
                ) : (
                  <>
                    {up.ok} ok · {up.pending} pending ·{" "}
                    <span style={{ color: up.error ? "var(--pf-t--global--text--color--status--danger--default)" : undefined }}>
                      {up.error} failing
                    </span>
                  </>
                )
              }
            />
          </GalleryItem>
        </Gallery>
      </GridItem>

      <GridItem span={12} lg={8}>
        <Card isFullHeight>
          <CardTitle>Activity, last {days} days</CardTitle>
          <CardBody>
            <ActivityChart activity={stats.activity} />
            <Content component="small">
              Built from the audit log. Downloads are counted only while{" "}
              <code>audit.log_downloads</code> is on; days are UTC.
            </Content>
          </CardBody>
        </Card>
      </GridItem>
      <GridItem span={12} lg={4}>
        <Card isFullHeight>
          <CardTitle>Storage by format</CardTitle>
          <CardBody>
            {slices.length === 0 ? (
              <Empty title="No packages yet">Publish a package to see usage here.</Empty>
            ) : (
              <FormatDonut slices={slices} />
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Repositories by size</CardTitle>
          <CardBody>
            {stats.repos.length === 0 ? (
              <Empty title="No repositories">Create one under Repositories.</Empty>
            ) : (
              <Table variant="compact" aria-label="Repositories by size">
                <Thead>
                  <Tr>
                    <Th>Repo</Th>
                    <Th>Mode</Th>
                    <Th modifier="fitContent">Packages</Th>
                    <Th width={30}>Size</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {stats.repos.slice(0, 10).map((r) => (
                    <Tr key={r.repo}>
                      <Td dataLabel="Repo">
                        <Link to={`/repos/${encodeURIComponent(r.repo)}`}>{r.repo}</Link>
                      </Td>
                      <Td dataLabel="Mode">
                        <ModeLabel mode={r.mode} />
                      </Td>
                      <Td dataLabel="Packages">{formatNumber(r.packages)}</Td>
                      <Td dataLabel="Size">
                        <Progress
                          value={(r.bytes / maxRepoBytes) * 100}
                          title={formatBytes(r.bytes)}
                          size="sm"
                          measureLocation={ProgressMeasureLocation.none}
                          aria-label={`${r.repo} size`}
                        />
                        <small>{formatBytes(r.bytes)}</small>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Recently published</CardTitle>
          <CardBody>
            {stats.recent_packages.length === 0 ? (
              <Empty title="Nothing published yet" />
            ) : (
              <Table variant="compact" aria-label="Recently published">
                <Thead>
                  <Tr>
                    <Th>Package</Th>
                    <Th>Format</Th>
                    <Th>Size</Th>
                    <Th>Published</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {stats.recent_packages.map((p) => (
                    <Tr key={p.id}>
                      <Td dataLabel="Package">
                        {p.name} <small>{packageVersion(p)}</small>
                        <br />
                        <small>
                          <Link to={`/repos/${encodeURIComponent(p.repo)}/${encodeURIComponent(p.channel)}`}>
                            {p.repo}/{p.channel}
                          </Link>
                        </small>
                        {p.origin_upstream && (
                          <>
                            {" "}
                            <Label isCompact variant="outline">
                              {p.origin_upstream}
                            </Label>
                          </>
                        )}
                      </Td>
                      <Td dataLabel="Format">
                        <FormatLabel format={p.format} />
                      </Td>
                      <Td dataLabel="Size">{formatBytes(p.size_bytes)}</Td>
                      <Td dataLabel="Published">
                        <Time seconds={p.published_at} />
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Audit activity, last {days} days</CardTitle>
          <CardBody>
            {stats.actions.length === 0 ? (
              <Empty title="No audit entries in this window" />
            ) : (
              <Table variant="compact" aria-label="Audit actions">
                <Thead>
                  <Tr>
                    <Th>Action</Th>
                    <Th modifier="fitContent">Count</Th>
                    <Th modifier="fitContent">Rejected</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {stats.actions.map((a) => (
                    <Tr key={a.action}>
                      <Td dataLabel="Action">
                        <Link to={`/audit?action=${encodeURIComponent(a.action)}`}>{a.action}</Link>
                      </Td>
                      <Td dataLabel="Count">{formatNumber(a.count)}</Td>
                      <Td dataLabel="Rejected">
                        {a.failures > 0 ? (
                          <Label isCompact color="red">
                            {formatNumber(a.failures)}
                          </Label>
                        ) : (
                          "0"
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>This server since it started</CardTitle>
          <CardBody>
            <DescriptionList isCompact isHorizontal columnModifier={{ default: "2Col" }}>
              <DescriptionListGroup>
                <DescriptionListTerm>Database</DescriptionListTerm>
                <DescriptionListDescription>
                  <Label isCompact color={run.database_up ? "green" : "red"}>
                    {run.database_up ? "reachable" : "unreachable"}
                  </Label>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Uptime</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatDuration(run.uptime_seconds)}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Publishes</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(run.publishes_ok)} ok · {formatNumber(run.publishes_failed)} failed
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Downloads</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(downloadsServed)} ({formatNumber(run.downloads_redirect)} redirected)
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Pull-through</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(run.pull_through_served)} served
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Upstream syncs</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(run.upstream_syncs_ok)} ok · {formatNumber(run.upstream_syncs_failed)} failed
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>API calls</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(run.grpc_ok)} ok · {formatNumber(run.grpc_error)} errors
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Rejected credentials</DescriptionListTerm>
                <DescriptionListDescription>
                  {formatNumber(run.auth_failures)}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <Content component="small" style={{ display: "block", marginTop: 12 }}>
              Counters live in this replica&apos;s memory: they restart with the process and cover
              only the requests it served.
            </Content>
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}
