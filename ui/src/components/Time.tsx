import { Tooltip } from "@patternfly/react-core";
import { formatRelative, formatTime } from "../format";

/** A timestamp as "3 hours ago", with the exact time on hover. */
export function Time({ seconds, never = "—" }: { seconds: number; never?: string }) {
  if (!seconds) return <>{never}</>;
  return (
    <Tooltip content={formatTime(seconds)}>
      <span>{formatRelative(seconds)}</span>
    </Tooltip>
  );
}
