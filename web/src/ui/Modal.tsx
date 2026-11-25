import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

/** Accessible dialog: labelled, Escape closes it, focus moves inside on open. */
export function Modal({
  title,
  description,
  onClose,
  children,
  role = "dialog",
}: {
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  role?: "dialog" | "alertdialog";
}) {
  const panel = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    if (typeof document === "undefined") return;
    document.addEventListener("keydown", onKey);
    panel.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);
  const titleId = "modal-title-" + title.replace(/\W+/g, "-").toLowerCase();
  return (
    <div
      className="modal-backdrop"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panel}
        className="modal"
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-header">
          <div>
            <h2 id={titleId} className="h3">
              {title}
            </h2>
            {description && <p className="card-desc">{description}</p>}
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-icon btn-sm"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={16} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
