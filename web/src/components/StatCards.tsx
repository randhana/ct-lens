import type { Results } from "../types";

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

/** A row of headline numbers summarising the scan. */
export function StatCards({ results }: { results: Results }) {
  const topCa = results.ca_shares[0];
  const cards: { label: string; value: string; sub?: string }[] = [
    { label: "Certificates", value: results.total_certificates.toLocaleString() },
    { label: "Unique domains", value: results.unique_domains.toLocaleString() },
    { label: "Wildcard certs", value: results.wildcard_count.toLocaleString() },
    {
      label: "Largest CA",
      value: topCa ? pct(topCa.share) : "—",
      sub: topCa?.issuer,
    },
    { label: "Top-3 CA share", value: pct(results.ca_concentration.top3) },
    {
      label: "Median lifetime",
      value: results.lifetimes.median_days != null ? `${results.lifetimes.median_days}d` : "—",
    },
  ];

  return (
    <div className="stat-grid">
      {cards.map((card) => (
        <div className="stat-card" key={card.label}>
          <div className="stat-value">{card.value}</div>
          <div className="stat-label">{card.label}</div>
          {card.sub && <div className="stat-sub">{card.sub}</div>}
        </div>
      ))}
    </div>
  );
}
