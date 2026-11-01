import { useMemo, useState } from "react";

// Cap how many rows we render at once so a large TLD (tens of thousands of
// domains) stays responsive. The filter narrows before we slice.
const RENDER_CAP = 500;

/** A searchable, scrollable list of every domain / subdomain discovered. */
export function DomainsList({ domains }: { domains: string[] }) {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? domains.filter((d) => d.includes(q)) : domains;
  }, [domains, query]);

  const shown = filtered.slice(0, RENDER_CAP);

  return (
    <section className="domains">
      <div className="domains-head">
        <h3>Domains &amp; subdomains ({domains.length.toLocaleString()})</h3>
        <input
          className="domains-filter"
          type="search"
          placeholder="Filter…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter domains"
        />
      </div>

      {filtered.length === 0 ? (
        <p className="muted">No domains match “{query}”.</p>
      ) : (
        <ul className="domains-grid">
          {shown.map((d) => (
            <li key={d} className="mono">
              {d}
            </li>
          ))}
        </ul>
      )}

      {filtered.length > RENDER_CAP && (
        <p className="muted domains-more">
          Showing {RENDER_CAP.toLocaleString()} of {filtered.length.toLocaleString()} — refine the
          filter, or use the CSV/JSON download for the full list.
        </p>
      )}
    </section>
  );
}
