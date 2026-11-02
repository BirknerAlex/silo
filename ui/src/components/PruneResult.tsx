import { Alert, Label } from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import type { RunPruneResponse } from "../api/types";
import { formatNumber, packageVersion } from "../format";
import { FormatLabel } from "./common";
import { Time } from "./Time";

/** What a prune run found (dry run) or did. */
export function PruneResult({ result }: { result: RunPruneResponse }) {
  const count = result.candidates.length;
  return (
    <>
      {result.dry_run ? (
        <Alert
          isInline
          variant={count ? "warning" : "info"}
          title={
            count
              ? `${formatNumber(count)} package${count === 1 ? "" : "s"} would be deleted`
              : "Nothing would be deleted"
          }
        >
          This was a dry run; no package was touched.
        </Alert>
      ) : (
        <Alert
          isInline
          variant={result.failed ? "danger" : "success"}
          title={`Deleted ${formatNumber(result.deleted)} package${result.deleted === 1 ? "" : "s"}${
            result.failed ? `; ${formatNumber(result.failed)} could not be deleted` : ""
          }`}
        />
      )}
      {count > 0 && (
        <Table variant="compact" aria-label="Prune candidates" style={{ marginTop: 16 }}>
          <Thead>
            <Tr>
              <Th>Package</Th>
              <Th>Repo / channel</Th>
              <Th>Format</Th>
              <Th>Arch</Th>
              <Th>Published</Th>
              <Th>Why</Th>
            </Tr>
          </Thead>
          <Tbody>
            {result.candidates.map((c) => (
              <Tr key={c.id}>
                <Td dataLabel="Package">
                  {c.name} <small>{packageVersion(c)}</small>
                </Td>
                <Td dataLabel="Repo / channel">
                  {c.repo}/{c.channel}
                </Td>
                <Td dataLabel="Format">
                  <FormatLabel format={c.format} />
                </Td>
                <Td dataLabel="Arch">{c.arch || "—"}</Td>
                <Td dataLabel="Published">
                  <Time seconds={c.published_at} />
                </Td>
                <Td dataLabel="Why">
                  {c.matched_rules.map((rule) => (
                    <Label key={rule} isCompact style={{ marginRight: 4 }}>
                      {rule}
                    </Label>
                  ))}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </>
  );
}
