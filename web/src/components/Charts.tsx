import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Results } from "../types";

// A small, colour-blind-friendly categorical palette for CA bars.
const PALETTE = [
  "#2b7bba", "#5aa469", "#c0587e", "#e1a73e", "#7e6bc4",
  "#49a7a0", "#b5693f", "#8aa23a", "#c65b5b", "#5f88a8",
];

const AXIS = "var(--muted)";
const GRID = "var(--border)";

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="chart-card">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

/** Horizontal bar chart of Certificate Authority market share. */
export function CAShareChart({ results }: { results: Results }) {
  const data = results.ca_shares.slice(0, 8).map((s) => ({
    issuer: s.issuer.length > 22 ? `${s.issuer.slice(0, 21)}…` : s.issuer,
    share: +(s.share * 100).toFixed(1),
  }));
  return (
    <ChartCard title="Certificate Authority market share">
      <ResponsiveContainer width="100%" height={Math.max(180, data.length * 38)}>
        <BarChart data={data} layout="vertical" margin={{ left: 12, right: 24 }}>
          <CartesianGrid horizontal={false} stroke={GRID} />
          <XAxis type="number" unit="%" stroke={AXIS} fontSize={12} />
          <YAxis type="category" dataKey="issuer" width={150} stroke={AXIS} fontSize={12} />
          <Tooltip formatter={(v) => `${v}%`} />
          <Bar dataKey="share" radius={[0, 4, 4, 0]}>
            {data.map((_, i) => (
              <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

/** Bar chart of certificate-lifetime buckets. */
export function LifetimeChart({ results }: { results: Results }) {
  const data = results.lifetimes.buckets.map(([bucket, count]) => ({ bucket, count }));
  return (
    <ChartCard title="Certificate lifetime distribution">
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={data} margin={{ left: 0, right: 12 }}>
          <CartesianGrid vertical={false} stroke={GRID} />
          <XAxis dataKey="bucket" stroke={AXIS} fontSize={11} />
          <YAxis stroke={AXIS} fontSize={12} allowDecimals={false} />
          <Tooltip />
          <Bar dataKey="count" fill="#5aa469" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}

/** Line chart of issuance volume per month. */
export function IssuanceChart({ results }: { results: Results }) {
  const data = results.issuance_by_month.map((p) => ({ period: p.period, count: p.count }));
  if (data.length === 0) return null;
  return (
    <ChartCard title="Issuance over time">
      <ResponsiveContainer width="100%" height={240}>
        <LineChart data={data} margin={{ left: 0, right: 12 }}>
          <CartesianGrid stroke={GRID} />
          <XAxis dataKey="period" stroke={AXIS} fontSize={11} />
          <YAxis stroke={AXIS} fontSize={12} allowDecimals={false} />
          <Tooltip />
          <Line type="monotone" dataKey="count" stroke="#c0587e" strokeWidth={2} dot={{ r: 3 }} />
        </LineChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
