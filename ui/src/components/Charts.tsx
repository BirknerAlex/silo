import {
  Chart,
  ChartAxis,
  ChartDonut,
  ChartGroup,
  ChartLegend,
  ChartLine,
  ChartVoronoiContainer,
} from "@patternfly/react-charts/victory";
import { useWidth } from "../hooks";
import { formatBytes, formatDay, formatNumber } from "../format";
import type { Stats } from "../api/types";

const SERIES = [
  { key: "publishes", name: "Publishes" },
  { key: "downloads", name: "Downloads" },
  { key: "failures", name: "Failures" },
] as const;

/** Daily publishes, downloads and rejected requests over the stats window. */
export function ActivityChart({ activity }: { activity: Stats["activity"] }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const height = 300;
  const maxValue = Math.max(
    1,
    ...activity.flatMap((d) => [d.publishes, d.downloads, d.failures]),
  );
  const labelEvery = Math.max(1, Math.ceil(activity.length / 8));

  return (
    <div ref={ref} className="chart-wrap" style={{ height, width: "100%" }}>
      {width > 0 && (
        <Chart
          ariaTitle="Daily activity"
          containerComponent={
            <ChartVoronoiContainer
              labels={({ datum }: { datum: { name: string; y: number } }) =>
                `${datum.name}: ${formatNumber(datum.y)}`
              }
              constrainToVisibleArea
            />
          }
          legendData={SERIES.map((s) => ({ name: s.name }))}
          legendComponent={<ChartLegend />}
          legendPosition="bottom"
          height={height}
          width={width}
          padding={{ bottom: 70, left: 60, right: 24, top: 16 }}
          domain={{ y: [0, maxValue] }}
          themeColor="multi-ordered"
        >
          <ChartAxis
            tickValues={activity.map((_, i) => i).filter((i) => i % labelEvery === 0)}
            tickFormat={(i: number) => formatDay(activity[i]?.day ?? 0)}
            fixLabelOverlap
          />
          <ChartAxis
            dependentAxis
            showGrid
            tickFormat={(v: number) => formatNumber(v)}
          />
          <ChartGroup>
            {SERIES.map((series) => (
              <ChartLine
                key={series.key}
                name={series.name}
                data={activity.map((d, i) => ({ name: series.name, x: i, y: d[series.key] }))}
              />
            ))}
          </ChartGroup>
        </Chart>
      )}
    </div>
  );
}

/** Where the storage goes, by package format. */
export function FormatDonut({
  slices,
}: {
  slices: { name: string; bytes: number; packages: number }[];
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const height = 300;
  const total = slices.reduce((sum, s) => sum + s.bytes, 0);

  return (
    <div ref={ref} className="chart-wrap" style={{ height, width: "100%" }}>
      {width > 0 && (
        <ChartDonut
          ariaTitle="Storage by format"
          constrainToVisibleArea
          data={slices.map((s) => ({ x: s.name, y: Math.max(s.bytes, 1) }))}
          labels={({ datum }: { datum: { x: string } }) => {
            const slice = slices.find((s) => s.name === datum.x);
            return slice
              ? `${slice.name}: ${formatBytes(slice.bytes)} · ${formatNumber(slice.packages)} pkg`
              : datum.x;
          }}
          legendData={slices.map((s) => ({ name: `${s.name} — ${formatBytes(s.bytes)}` }))}
          legendOrientation="vertical"
          legendPosition="right"
          height={height}
          width={width}
          padding={{ bottom: 20, left: 20, right: Math.min(220, width / 2), top: 20 }}
          subTitle="stored"
          title={formatBytes(total)}
          themeColor="multi-ordered"
        />
      )}
    </div>
  );
}
