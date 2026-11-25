# AgentSecret visual design

This document records the visual system for the public site and the signed-in
dashboard. It is not a security or compatibility specification.

## Direction

White minimalism with a left-hand dashboard navigation. The interface should
read as a precise, quiet tool: plenty of white space, 1px hairlines, one ink
colour for primary actions and a single emerald accent for state ("on",
"allowed", "current page"). No decorative gradients, glow, stock photography
or invented metrics. Every number shown must come from the server.

## Two surfaces, one system

- **Public site** (`src/landing/*`): sticky header with anchor links, hero,
  facts grid, how-it-works, integrations, plan, FAQ and footer. Under 900px the
  header links collapse into a menu button.
- **Dashboard** (`src/dashboard/*`): `app-shell` grid with a 248px sidebar and
  a sticky top bar. Under 900px the sidebar becomes an off-canvas drawer with a
  scrim. Signed-out visitors see `AuthGate` (no data, no stand-in identity).
- **Server-rendered pages** (`/device`, OAuth consent, device review) use the
  inline shell in `src/security/primitives.ts` with the same palette; their CSP
  forbids external styles, fonts, images and scripts.

## Tokens (`src/index.css`)

| Group   | Tokens                                                                                                             |
| ------- | ------------------------------------------------------------------------------------------------------------------ |
| Surface | `--bg-canvas #fff`, `--bg-surface #fafbfc`, `--bg-subtle #f8fafc`, `--bg-hover #f1f5f9`, `--bg-inverse #0f172a`    |
| Lines   | `--border-subtle #e2e8f0`, `--border-medium #cbd5e1`, `--border-strong #94a3b8`                                    |
| Text    | `--text-primary #0f172a`, `--text-secondary #475569`, `--text-tertiary #64748b`, `--text-disabled #94a3b8`         |
| Signals | `--accent #059669` (emerald), `--info #2563eb`, `--warn #b45309`, `--danger #e11d48`, each with `-light`/`-border` |
| Type    | system sans stack; `--font-mono` for references, commands and IDs; scale `--text-xs` … `--text-hero`               |
| Space   | 4px scale `--space-1` … `--space-20`                                                                               |
| Shape   | `--radius-sm 6` · `md 8` · `lg 12` · `xl 16` · `full`                                                              |

Small text uses `--text-tertiary` or darker so it keeps at least 4.5:1 contrast
on white; `--text-disabled` is for disabled controls only.

## Components (CSS classes)

- **Buttons**: `.btn` + `-primary` (ink), `-accent`, `-secondary`, `-ghost`,
  `-danger` (soft), `-danger-solid`; sizes `-sm`, `-lg`; `-icon`, `-block`.
- **Surfaces**: `.card` (`-tight`), `.card-flat`, `.card-header`,
  `.card-title`, `.card-desc`.
- **Forms**: `.form`, `.form-grid` (2 columns → 1 under 640px), `.field`,
  `.label`, `.hint`, `.input` / `.select` / `.textarea` (`.input-mono`),
  `.check`, `.fieldset`, `.form-actions`.
- **Feedback**: `.notice` + `-info` / `-success` / `-warn` / `-error`,
  `.badge` + variants, `.dot`, `.empty-state`, `.skeleton`.
- **Data**: `.table-wrap` + `.table` (horizontal scroll on small screens),
  `.list` / `.list-item`, `.code-block`, `.code-inline`, `.meter`.
- **Overlays**: `Modal` and `ConfirmDialog` (`src/ui/*`) — labelled dialog,
  Escape closes, focus moves inside. Destructive actions (disconnect a vault,
  revoke an executor, revoke all sessions) always confirm first.

## Rules

1. Style with classes from `index.css`; inline `style` only for genuinely
   dynamic values (for example a meter width) or one-off spacing.
2. Status messages use `role="status"` with `.notice-info`/`-success`; errors
   use `role="alert"` with `.notice-error`.
3. Every form control has a visible label or an `aria-label`; icon-only
   buttons have an `aria-label`.
4. Show loading and empty states explicitly; never show an empty state while
   data is still loading.
5. Keep the dashboard usable at 375px: no horizontal page scroll, tables and
   code scroll inside their own containers.
