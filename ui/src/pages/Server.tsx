import {
  Alert,
  Button,
  Card,
  CardBody,
  CardTitle,
  ClipboardCopy,
  Content,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Grid,
  GridItem,
  Label,
  LabelGroup,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useState } from "react";
import { api } from "../api";
import type { ServerInfo } from "../api/types";
import { Body, PageHeader, Query } from "../components/common";
import { generateUpstreamSecretKey } from "../format";
import { useAsync } from "../hooks";

function Flag({ on, yes = "on", no = "off" }: { on: boolean; yes?: string; no?: string }) {
  return (
    <Label isCompact color={on ? "green" : "grey"}>
      {on ? yes : no}
    </Label>
  );
}

export function Server() {
  const info = useAsync(() => api.serverInfo(), []);
  return (
    <>
      <PageHeader title="Server" subtitle="How this server is configured. Secrets are never shown." />
      <Body>
        <Query state={info}>{(s) => <ServerBody info={s} />}</Query>
      </Body>
    </>
  );
}

function ServerBody({ info }: { info: ServerInfo }) {
  const [key, setKey] = useState<string>();
  return (
    <Grid hasGutter>
      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Build</CardTitle>
          <CardBody>
            <DescriptionList isHorizontal isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Version</DescriptionListTerm>
                <DescriptionListDescription>{info.version}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Commit</DescriptionListTerm>
                <DescriptionListDescription>
                  <code>{info.commit}</code>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Built</DescriptionListTerm>
                <DescriptionListDescription>{info.built_at}</DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Formats</DescriptionListTerm>
                <DescriptionListDescription>
                  <LabelGroup>
                    {info.formats.map((f) => (
                      <Label key={f} isCompact>
                        {f}
                      </Label>
                    ))}
                  </LabelGroup>
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Public URL</DescriptionListTerm>
                <DescriptionListDescription>
                  {info.public_base_url || <em>derived from each request</em>}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Sign-in</CardTitle>
          <CardBody>
            <DescriptionList isHorizontal isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Password</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.password_login_enabled} yes="enabled" no="disabled" />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Single sign-on</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.oidc_enabled} yes="enabled" no="not configured" />
                  {info.oidc_enabled && (
                    <>
                      {" "}
                      <code>{info.oidc_issuer}</code>
                    </>
                  )}
                </DescriptionListDescription>
              </DescriptionListGroup>
              {info.oidc_enabled && (
                <>
                  <DescriptionListGroup>
                    <DescriptionListTerm>SSO only</DescriptionListTerm>
                    <DescriptionListDescription>
                      <Flag on={info.oidc_exclusive} />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                  <DescriptionListGroup>
                    <DescriptionListTerm>Username linking</DescriptionListTerm>
                    <DescriptionListDescription>
                      <Flag on={info.oidc_allow_username_linking} />
                    </DescriptionListDescription>
                  </DescriptionListGroup>
                </>
              )}
              <DescriptionListGroup>
                <DescriptionListTerm>Session lifetime</DescriptionListTerm>
                <DescriptionListDescription>
                  {info.session_ttl_hours} hours ({Math.round(info.session_ttl_hours / 24)} days)
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            {info.oidc_enabled && info.oidc_allow_username_linking && (
              <Alert isInline variant="warning" title="Username linking is on" style={{ marginTop: 16 }}>
                A first single sign-on login can take over a local account with the same username.
                Turn it off once your accounts are migrated.
              </Alert>
            )}
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Features</CardTitle>
          <CardBody>
            <DescriptionList isHorizontal isCompact>
              <DescriptionListGroup>
                <DescriptionListTerm>Signing</DescriptionListTerm>
                <DescriptionListDescription>
                  {info.signing.length ? (
                    <LabelGroup>
                      {info.signing.map((f) => (
                        <Label key={f} isCompact color="green">
                          {f}
                        </Label>
                      ))}
                    </LabelGroup>
                  ) : (
                    <Label isCompact color="grey">
                      none configured
                    </Label>
                  )}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Pruning</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.prune_enabled} yes="enabled" no="disabled" />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Upstream credentials</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.upstream_secret_configured} yes="key configured" no="no key" />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Audit: downloads</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.audit_log_downloads} />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Audit: pull-through</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.audit_log_pull_through} />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Audit retention</DescriptionListTerm>
                <DescriptionListDescription>
                  {info.audit_retention_days > 0 ? `${info.audit_retention_days} days` : "kept forever"}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Metrics</DescriptionListTerm>
                <DescriptionListDescription>
                  <Flag on={info.metrics_enabled} />{" "}
                  {info.metrics_enabled && (
                    <a href="/metrics" target="_blank" rel="noopener noreferrer">
                      /metrics
                    </a>
                  )}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Signing keys</DescriptionListTerm>
                <DescriptionListDescription>
                  <a href="/RPM-GPG-KEY-silo" target="_blank" rel="noopener noreferrer">
                    RPM/deb/flatpak public key
                  </a>
                  {" · "}
                  <a href="/pacman-signing-key" target="_blank" rel="noopener noreferrer">
                    pacman public key
                  </a>
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12} lg={6}>
        <Card isFullHeight>
          <CardTitle>Scheduled jobs</CardTitle>
          <CardBody>
            <Table variant="compact" aria-label="Scheduled jobs">
              <Thead>
                <Tr>
                  <Th>Job</Th>
                  <Th>Schedule</Th>
                </Tr>
              </Thead>
              <Tbody>
                {info.jobs.map((j) => (
                  <Tr key={j.name}>
                    <Td dataLabel="Job">{j.name}</Td>
                    <Td dataLabel="Schedule">
                      {j.enabled ? <code>{j.schedule}</code> : <Label isCompact>off</Label>}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
            <Content component="small" style={{ display: "block", marginTop: 8 }}>
              Six-field cron, seconds first. Set in the server configuration under <code>jobs</code>.
            </Content>
          </CardBody>
        </Card>
      </GridItem>

      <GridItem span={12}>
        <Card>
          <CardTitle>Generate an upstream secret key</CardTitle>
          <CardBody>
            <Content component="p">
              The encryption key for pull-through upstream credentials (<code>upstream_secret.key</code>).
              It is generated here in your browser from 32 random bytes and is not sent anywhere. Rotating a
              key invalidates every stored upstream credential.
            </Content>
            <Button variant="secondary" onClick={() => setKey(generateUpstreamSecretKey())}>
              {key ? "Generate another" : "Generate key"}
            </Button>
            {key && (
              <div style={{ marginTop: 16, maxWidth: 560 }}>
                <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied">
                  {key}
                </ClipboardCopy>
              </div>
            )}
          </CardBody>
        </Card>
      </GridItem>
    </Grid>
  );
}
