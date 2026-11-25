import type { AppController } from "../app/useAppController";

export function OnboardingForm({ c }: { c: AppController }) {
  const {
    handleOnboarding,
    onboardingName,
    onboardingStatus,
    setOnboardingName,
  } = c;
  return (
    <form
      onSubmit={handleOnboarding}
      style={{
        margin: "0 auto",
        maxWidth: "1160px",
        padding: "14px 24px",
        display: "flex",
        flexWrap: "wrap",
        gap: "10px",
        alignItems: "center",
        background: "#eff6ff",
        borderBottom: "1px solid #dbeafe",
        color: "#1e3a8a",
        fontSize: 13,
      }}
    >
      <strong>Finish setting up your account.</strong>
      <span>
        Pick the display name this account uses. No email confirmation is
        required.
      </span>
      <input
        aria-label="Display name"
        value={onboardingName}
        onChange={(e) => setOnboardingName(e.target.value)}
        placeholder="Display name"
        style={{
          padding: "7px 10px",
          borderRadius: "6px",
          border: "1px solid #93c5fd",
          fontSize: 13,
        }}
      />
      <button
        type="submit"
        style={{
          padding: "7px 12px",
          borderRadius: "6px",
          border: "none",
          background: "#1d4ed8",
          color: "#ffffff",
          fontWeight: 600,
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        Save
      </button>
      {onboardingStatus === "error" && (
        <span role="alert" style={{ color: "#b91c1c" }}>
          Could not save your display name. Retry.
        </span>
      )}
    </form>
  );
}
