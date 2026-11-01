import type { Finding } from "../types";

/** A severity-ordered table of security findings. */
export function Findings({ findings }: { findings: Finding[] }) {
  return (
    <section className="findings">
      <h3>Security findings ({findings.length})</h3>
      {findings.length === 0 ? (
        <p className="muted">No findings.</p>
      ) : (
        <table className="findings-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Category</th>
              <th>Domain</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={`${f.cert_id}-${f.domain}-${i}`}>
                <td>
                  <span className={`badge badge-${f.severity}`}>{f.severity}</span>
                </td>
                <td>{f.category}</td>
                <td className="mono">{f.domain}</td>
                <td>{f.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
