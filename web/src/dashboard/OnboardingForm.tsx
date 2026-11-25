import type { AppController } from "../app/useAppController";

export function OnboardingForm({ c }: { c: AppController }) {
  const {
    handleOnboarding,
    onboardingName,
    onboardingStatus,
    setOnboardingName,
  } = c;
  return (
    <form onSubmit={handleOnboarding} className="notice notice-info">
      <div className="notice-body stack-sm">
        <div>
          <strong>Finish setting up your account.</strong>{" "}
          <span>
            Pick the display name this account uses. No email confirmation is
            required.
          </span>
        </div>
        <div className="row">
          <input
            className="input"
            style={{ maxWidth: 280 }}
            aria-label="Display name"
            value={onboardingName}
            onChange={(e) => setOnboardingName(e.target.value)}
            placeholder="Display name"
          />
          <button type="submit" className="btn btn-primary">
            Save
          </button>
        </div>
        {onboardingStatus === "error" && (
          <span
            className="notice notice-error"
            role="alert"
            style={{ color: "var(--danger-strong)" }}
          >
            Could not save your display name. Retry.
          </span>
        )}
      </div>
    </form>
  );
}
