import { executorProof, createExecutorIdentity } from "../cli/browser/executor";
import {
  ExecutorStore,
  macOsExecutorBackend,
} from "../cli/browser/executor-store";

async function main() {
  if (process.platform !== "darwin") throw new Error("macos_only");
  const store = new ExecutorStore(macOsExecutorBackend());
  const existing = await store.load();
  if (existing) {
    console.log("executor identity already present; acceptance skipped");
    return;
  }
  const identity = await createExecutorIdentity();
  await store.save(identity);
  try {
    const loaded = await store.load();
    if (!loaded || loaded.executorId !== identity.executorId)
      throw new Error("keychain_readback_mismatch");
    const proof = await executorProof(
      loaded,
      "POST",
      "https://agentsecret.astronlab.com/api/executor/enroll",
    );
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(proof))
      throw new Error("executor_proof_invalid");
    console.log("executor Keychain acceptance passed");
  } finally {
    store.remove();
  }
}

main().catch((error) => {
  console.error(
    error instanceof Error
      ? error.message
      : "executor_keychain_acceptance_failed",
  );
  process.exitCode = 1;
});
