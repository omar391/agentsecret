import type { ReactNode } from "react";

/** Title block at the top of each dashboard tab. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="row-between" style={{ alignItems: "flex-end" }}>
      <div className="page-header">
        <h1 className="h1">{title}</h1>
        {description && <p className="muted">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
