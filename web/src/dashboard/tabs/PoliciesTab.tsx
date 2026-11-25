import type { AppController } from "../../app/useAppController";
import { ExecutorsGrantsPanel } from "../policies/ExecutorsGrantsPanel";
import { PolicyForm } from "../policies/PolicyForm";
import { PolicyList } from "../policies/PolicyList";

export function PoliciesTab({ c }: { c: AppController }) {
  void c;
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "16px",
      }}
    >
      <PolicyForm c={c} />

      <PolicyList c={c} />

      <ExecutorsGrantsPanel c={c} />
    </div>
  );
}
