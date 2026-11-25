import type { AppController } from "../../app/useAppController";
import { ExecutorsGrantsPanel } from "../policies/ExecutorsGrantsPanel";
import { PolicyForm } from "../policies/PolicyForm";
import { PolicyList } from "../policies/PolicyList";
import { PageHeader } from "../PageHeader";

export function PoliciesTab({ c }: { c: AppController }) {
  return (
    <>
      <PageHeader
        title="Secret Policies"
        description="Bind each secret alias to the exact destinations an agent may call, then manage protected local executors."
      />
      <PolicyForm c={c} />
      <PolicyList c={c} />
      <ExecutorsGrantsPanel c={c} />
    </>
  );
}
