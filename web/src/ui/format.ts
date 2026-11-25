/** Deterministic UTC timestamp, e.g. "2026-11-25 14:03 UTC". Falls back to the raw value. */
export function formatTimestamp(
  value: string | number | null | undefined,
): string {
  if (value === null || value === undefined || value === "") return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const iso = date.toISOString();
  return iso.slice(0, 10) + " " + iso.slice(11, 16) + " UTC";
}
