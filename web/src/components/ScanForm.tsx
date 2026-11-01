import { useState } from "react";

interface Props {
  disabled: boolean;
  onScan: (target: string, anonymize: boolean) => void;
}

/** The query bar: a TLD/domain input, an anonymise toggle, and a run button. */
export function ScanForm({ disabled, onScan }: Props) {
  const [target, setTarget] = useState(".lk");
  const [anonymize, setAnonymize] = useState(true);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = target.trim();
    if (trimmed) {
      onScan(trimmed, anonymize);
    }
  }

  return (
    <form className="scan-form" onSubmit={submit}>
      <input
        aria-label="TLD or domain"
        className="scan-input"
        value={target}
        placeholder=".lk, example.com, %.lk"
        onChange={(e) => setTarget(e.target.value)}
        disabled={disabled}
      />
      <label className="scan-toggle">
        <input
          type="checkbox"
          checked={anonymize}
          onChange={(e) => setAnonymize(e.target.checked)}
          disabled={disabled}
        />
        Anonymise findings
      </label>
      <button className="scan-button" type="submit" disabled={disabled}>
        {disabled ? "Scanning…" : "Analyse"}
      </button>
    </form>
  );
}
