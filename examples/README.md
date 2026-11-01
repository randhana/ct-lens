# Example output

`sample-gov-lk/` is a **sample report bundle** produced by ct-lens, generated with:

```bash
ct-lens report gov.lk -o examples/sample-gov-lk
```

> ⚠️ **Synthetic data.** This sample was generated from the small, *fictitious*
> fixture in `tests/fixtures/` (not a live crt.sh pull), so the numbers are
> illustrative only — they show the *shape* of the output, not real `.lk` data.
> Run the tool yourself for real results.

The bundle contains everything a run produces:

| File | What it is |
| --- | --- |
| `report.md` | The human-readable Markdown report |
| `dataset.csv` / `dataset.json` | The machine-readable certificate dataset |
| `ca_shares.png` | CA market-share chart |
| `lifetimes.png` | Certificate-lifetime distribution chart |
| `issuance_over_time.png` | Issuance-over-time chart |
