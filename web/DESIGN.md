# AgentSecret visual design reference

Preserved authored visual intent. This is not a security or compatibility specification; [the architecture](../ARCHITECTURE.md) governs implemented behavior.

## Phase 1: Strategic Vibe Discovery & Narrative Positioning

### 1. Real-World Anchor

- **Artifact**: **1970s Cryptographic Key Distribution Module & Swiss High-Frequency Telemetry Rack**.
- Heavy matte chassis, tactile toggle switches, high-density monospaced readout meters, razor-sharp 1px hairline dividers, precise numeric status indicators, and cold carbon ink.
- _Not_ a generic purple-glow SaaS landing page. _Not_ a web3 hype token launch. _Not_ a pastel wellness mobile app.

### 2. Primary Emotional Response (First 3 Seconds)

- **Velocity & Cryptographic Authority**: Utter certainty, mathematical precision, zero marketing ambiguity. The developer immediately grasps: _“This broker keeps upstream credentials inside its trusted execution boundary.”_

### 3. Influence Collision

- **Swiss Utilitarian Typography & Grid Rigor** (Max Huber, Josef Müller-Brockmann)
  ×
- **Hardened Edge Security Infrastructure** (Cloudflare V8 Isolates, Hardware Security Modules).

### 4. Negative Guardrails (What It Must NEVER Be)

1. **No AI Slop / Purple Radial Gradients**: Strictly zero `radial-gradient(ellipse, rgba(147, 51, 234, ...))` or violet neon glows.
2. **No Unstyled Emojis as UI**: Every icon is a single-weight stroked SVG (Lucide 1.5px/2px).
3. **No Symmetrical Bento Grid / Vanity Numbers**: Asymmetrical spatial rhythm (60/40 split viewports, offset technical panels, authentic runtime metrics like latency and redaction counts).

---

## Phase 2: Visual Archetype & Design System Architecture

### 1. Archetype Commitment: Archetype B (Swiss Technical / Utilitarian)

- **Canvas**: Deep Obsidian & Carbon (`oklch(0.12 0.01 260)` / `#090a0f`).
- **Surfaces**: Layered matte panels with 1px hairline structural borders (`rgba(255, 255, 255, 0.09)`).
- **Typography**:
  - Display & Section Titles: Technical Sans (`Plus Jakarta Sans` / `-apple-system, BlinkMacSystemFont`) with tight tracking (`-0.03em`).
  - Monospace & Metadata: Precision Monospace (`ui-monospace, SFMono-Regular, Menlo, monospace`) with wide tracking (`+0.05em`) for statuses, endpoints, and hashes.
- **Accent Token**:
  - Primary Signal: **Emerald Cryptographic Green** (`oklch(0.72 0.19 152)` / `#10b981`) for verified isolation, active edge bindings, and valid tokens.
  - Secondary Signal: **Electric Signal Blue** (`oklch(0.68 0.18 240)` / `#3b82f6`) for proxy routing and OAuth sessions.
  - Critical Signal: **Coral Red** (`oklch(0.62 0.22 25)` / `#f43f5e`) for SSRF violations and exfiltration attempts.

### 2. WCAG AAA Contrast

- Primary Headline text: `oklch(0.97 0.005 260)` ($\ge 12:1$ contrast against base canvas).
- Body copy: `oklch(0.78 0.01 260)` ($\ge 7.5:1$ contrast).
- Muted metadata: `oklch(0.55 0.01 260)` ($\ge 4.5:1$ contrast).
