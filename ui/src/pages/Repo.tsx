import {
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Card,
  CardBody,
  CardTitle,
  Form,
  FormGroup,
  Grid,
  GridItem,
  InputGroup,
  InputGroupItem,
  TextInput,
  Content,
  Flex,
  FlexItem,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import { RepoMode } from "../api/types";
import { useAuth } from "../auth";
import { Body, Empty, FormatLabel, ModeLabel, PageHeader, Query } from "../components/common";
import { formatBytes, formatNumber } from "../format";
import { useAsync } from "../hooks";
import { DeleteRepoModal, ModeModal } from "./Repos";

export function Repo() {
  const { repo = "" } = useParams();
  const { capabilities } = useAuth();
  const navigate = useNavigate();
  const rows = useAsync(
    async () => (await api.listRepos()).filter((r) => r.repo === repo),
    [repo],
  );
  const [channel, setChannel] = useState("");
  const [toggling, setToggling] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const summary = useMemo(() => {
    const list = rows.data ?? [];
    return {
      mode: list[0]?.mode ?? RepoMode.Private,
      packages: list.reduce((n, r) => n + r.package_count, 0),
      bytes: list.reduce((n, r) => n + r.total_bytes, 0),
    };
  }, [rows.data]);

  const open = (e: FormEvent) => {
    e.preventDefault();
    if (channel.trim()) navigate(`/repos/${encodeURIComponent(repo)}/${encodeURIComponent(channel.trim())}`);
  };

  return (
    <>
      <PageHeader
        title={repo}
        breadcrumb={
          <Breadcrumb style={{ marginBottom: 8 }}>
            <BreadcrumbItem to="/admin/repos" onClick={(e) => { e.preventDefault(); navigate("/repos"); }}>
              Repositories
            </BreadcrumbItem>
            <BreadcrumbItem isActive>{repo}</BreadcrumbItem>
          </Breadcrumb>
        }
        subtitle={
          rows.data && (
            <>
              <ModeLabel mode={summary.mode} /> · {formatNumber(summary.packages)} packages ·{" "}
              {formatBytes(summary.bytes)}
            </>
          )
        }
        actions={
          capabilities.admin && (
            <Flex spaceItems={{ default: "spaceItemsSm" }}>
              <FlexItem>
                <Button variant="secondary" onClick={() => setToggling(true)}>
                  {summary.mode === RepoMode.Public ? "Make private" : "Make public"}
                </Button>
              </FlexItem>
              <FlexItem>
                <Button variant="danger" onClick={() => setDeleting(true)}>
                  Delete
                </Button>
              </FlexItem>
            </Flex>
          )
        }
      />
      <Body>
        <Grid hasGutter>
          <GridItem span={12}>
            <Card>
              <CardTitle>Channels</CardTitle>
              <CardBody>
                <Query state={rows}>
                  {(list) =>
                    list.every((r) => !r.channel) ? (
                      <Empty title="No packages yet">
                        Channels appear with the first publish. You can configure a channel&apos;s
                        upstreams and retention ahead of that by opening it by name below.
                      </Empty>
                    ) : (
                      <Table aria-label="Channels" variant="compact">
                        <Thead>
                          <Tr>
                            <Th>Channel</Th>
                            <Th>Format</Th>
                            <Th modifier="fitContent">Packages</Th>
                            <Th modifier="fitContent">Size</Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {list
                            .filter((r) => r.channel)
                            .map((r) => (
                              <Tr key={`${r.channel}/${r.format}`}>
                                <Td dataLabel="Channel">
                                  <Link
                                    to={`/repos/${encodeURIComponent(repo)}/${encodeURIComponent(r.channel)}?format=${r.format}`}
                                  >
                                    {r.channel}
                                  </Link>
                                </Td>
                                <Td dataLabel="Format">
                                  <FormatLabel format={r.format} />
                                </Td>
                                <Td dataLabel="Packages">{formatNumber(r.package_count)}</Td>
                                <Td dataLabel="Size" modifier="nowrap">{formatBytes(r.total_bytes)}</Td>
                              </Tr>
                            ))}
                        </Tbody>
                      </Table>
                    )
                  }
                </Query>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem span={12} md={6}>
            <Card>
              <CardTitle>Open a channel by name</CardTitle>
              <CardBody>
                <Form onSubmit={open}>
                  <FormGroup fieldId="channel-name">
                    <InputGroup>
                      <InputGroupItem isFill>
                        <TextInput
                          id="channel-name"
                          aria-label="Channel name"
                          placeholder="stable"
                          value={channel}
                          onChange={(_, v) => setChannel(v)}
                        />
                      </InputGroupItem>
                      <InputGroupItem>
                        <Button type="submit" variant="control" isDisabled={!channel.trim()}>
                          Open
                        </Button>
                      </InputGroupItem>
                    </InputGroup>
                  </FormGroup>
                </Form>
                <Content component="small">
                  Upstreams and retention rules belong to a repo/channel pair and can be set before
                  anything is published to it.
                </Content>
              </CardBody>
            </Card>
          </GridItem>
        </Grid>
      </Body>
      {toggling && (
        <ModeModal
          repo={{ repo, mode: summary.mode }}
          onClose={() => setToggling(false)}
          onDone={() => {
            setToggling(false);
            rows.reload();
          }}
        />
      )}
      {deleting && (
        <DeleteRepoModal
          repo={{ repo, packages: summary.packages }}
          onClose={() => setDeleting(false)}
          onDone={() => navigate("/repos")}
        />
      )}
    </>
  );
}
