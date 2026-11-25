import type { ReactNode } from "react";
import { Modal } from "./Modal";

/** Confirmation for destructive actions. The confirm label is the button's only text. */
export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}) {
  return (
    <Modal title={title} onClose={onCancel} role="alertdialog">
      <div className="stack">
        <div className="muted small">{body}</div>
        <div className="form-actions" style={{ justifyContent: "flex-end" }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-danger-solid"
            onClick={async () => {
              onCancel();
              await onConfirm();
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
