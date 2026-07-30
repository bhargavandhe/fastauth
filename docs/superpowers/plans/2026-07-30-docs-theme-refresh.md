# Documentation Theme Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore Python syntax highlighting and give the MkDocs Material site a restrained fastauth teal-and-amber identity.

**Architecture:** Keep MkDocs Material and its templates unchanged. Configure the Markdown rendering pipeline in `mkdocs.yml`, then layer narrowly scoped visual adjustments through one stylesheet loaded with `extra_css`.

**Tech Stack:** MkDocs 1.6, MkDocs Material 9.7, Python-Markdown, PyMdown Extensions, Pygments, CSS

## Global Constraints

- Retain MkDocs Material, the existing navigation, search, API reference, light/dark modes, code-copy buttons, and annotations.
- Use deep teal as the primary color and warm amber as the accent.
- Do not add custom templates, JavaScript, remote assets, external fonts, or new documentation content.
- Preserve the canonical site URL `https://bhargavandhe.github.io/fastauth/`.

---

### Task 1: Syntax highlighting and theme configuration

**Files:**
- Modify: `mkdocs.yml`
- Create: `docs/stylesheets/extra.css`

**Interfaces:**
- Consumes: Existing language-tagged Markdown fences such as ` ```python ` and the MkDocs Material dependency set.
- Produces: Pygments token markup, language classes, teal/amber palette metadata, and a loaded custom stylesheet.

- [ ] **Step 1: Build the current site and verify the highlighting assertion fails**

Run:

```bash
uv run --extra docs mkdocs build --strict --site-dir /tmp/fastauth-docs-red
rg 'class="k"' /tmp/fastauth-docs-red/quickstart/index.html
```

Expected: the strict build succeeds, but `rg` exits with status 1 because the
current Markdown configuration emits no Pygments keyword spans.

- [ ] **Step 2: Add the rendering and palette configuration**

Update `mkdocs.yml` with:

```yaml
theme:
  name: material
  features:
    - navigation.tabs
    - navigation.sections
    - navigation.expand
    - content.code.copy
    - content.code.annotate
  palette:
    - media: "(prefers-color-scheme: light)"
      scheme: default
      primary: teal
      accent: amber
      toggle:
        icon: material/weather-night
        name: Switch to dark mode
    - media: "(prefers-color-scheme: dark)"
      scheme: slate
      primary: teal
      accent: amber
      toggle:
        icon: material/weather-sunny
        name: Switch to light mode

markdown_extensions:
  - attr_list
  - pymdownx.highlight:
      anchor_linenums: true
      line_spans: __span
      pygments_lang_class: true
  - pymdownx.inlinehilite
  - pymdownx.superfences

extra_css:
  - stylesheets/extra.css
```

Create `docs/stylesheets/extra.css` as an empty file so the configured asset
exists while the rendering change is validated.

- [ ] **Step 3: Build and verify syntax token output and configured assets**

Run:

```bash
uv run --extra docs mkdocs build --strict --site-dir /tmp/fastauth-docs-green
rg 'class="k"' /tmp/fastauth-docs-green/quickstart/index.html
rg 'class="language-python"' /tmp/fastauth-docs-green/quickstart/index.html
rg 'stylesheets/extra.css' /tmp/fastauth-docs-green/quickstart/index.html
```

Expected: the build and all three assertions pass.

- [ ] **Step 4: Commit the rendering configuration**

```bash
git add mkdocs.yml docs/stylesheets/extra.css
git commit -m "docs: enable syntax highlighting"
```

### Task 2: Restrained fastauth visual identity

**Files:**
- Modify: `docs/stylesheets/extra.css`

**Interfaces:**
- Consumes: MkDocs Material color variables and stable `.md-*`/`.md-typeset` selectors.
- Produces: Accessible light/dark brand colors and focused header, heading, link, and code-block styling.

- [ ] **Step 1: Verify the brand-style assertion fails**

Run:

```bash
rg -- '--fastauth-primary: #0f766e' docs/stylesheets/extra.css
```

Expected: `rg` exits with status 1 because the stylesheet is empty.

- [ ] **Step 2: Add the custom styles**

Replace `docs/stylesheets/extra.css` with:

```css
[data-md-color-scheme="default"] {
  --fastauth-primary: #0f766e;
  --fastauth-primary-light: #0d9488;
  --fastauth-accent: #d97706;
  --fastauth-border: rgba(15, 118, 110, 0.22);
  --md-primary-fg-color: var(--fastauth-primary);
  --md-primary-fg-color--light: var(--fastauth-primary-light);
  --md-primary-fg-color--dark: #115e59;
  --md-accent-fg-color: var(--fastauth-accent);
}

[data-md-color-scheme="slate"] {
  --fastauth-primary: #0f766e;
  --fastauth-primary-light: #2dd4bf;
  --fastauth-accent: #f59e0b;
  --fastauth-border: rgba(45, 212, 191, 0.24);
  --md-primary-fg-color: var(--fastauth-primary);
  --md-primary-fg-color--light: var(--fastauth-primary-light);
  --md-primary-fg-color--dark: #115e59;
  --md-accent-fg-color: var(--fastauth-accent);
}

.md-header {
  border-bottom: 0.18rem solid var(--fastauth-accent);
  box-shadow: none;
}

.md-typeset h1,
.md-typeset h2,
.md-typeset h3 {
  font-weight: 650;
  letter-spacing: -0.015em;
}

.md-typeset a {
  text-decoration-thickness: 0.08em;
  text-underline-offset: 0.16em;
}

.md-typeset .highlight {
  border: 1px solid var(--fastauth-border);
  border-left: 0.2rem solid var(--fastauth-accent);
  border-radius: 0.35rem;
  overflow: hidden;
}

.md-typeset .highlight pre {
  margin: 0;
}

.md-typeset code {
  border-radius: 0.2rem;
}

:focus-visible {
  outline: 0.14rem solid var(--fastauth-accent);
  outline-offset: 0.14rem;
}
```

- [ ] **Step 3: Build and validate the complete site**

Run:

```bash
uv run --extra docs mkdocs build --strict --site-dir site
rg -- '--fastauth-primary: #0f766e' site/stylesheets/extra.css
rg 'class="k"' site/quickstart/index.html
rg 'rel="canonical" href="https://bhargavandhe.github.io/fastauth/' site/index.html
git diff --check
```

Expected: every command exits successfully.

- [ ] **Step 4: Inspect representative pages**

Serve the generated site locally and inspect the introduction, quickstart, and
reference pages in light and dark modes at desktop and narrow widths. Confirm
that navigation, search, code copy, syntax colors, focus indicators, and code
block borders remain usable.

- [ ] **Step 5: Commit the visual refresh**

```bash
git add docs/stylesheets/extra.css
git commit -m "docs: add fastauth theme styling"
```

### Task 3: Final verification and delivery

**Files:**
- Verify: `mkdocs.yml`
- Verify: `docs/stylesheets/extra.css`
- Verify: `.github/workflows/docs-pages.yml`

**Interfaces:**
- Consumes: The completed configuration and styles from Tasks 1 and 2.
- Produces: A verified feature branch ready to merge and deploy through GitHub Pages.

- [ ] **Step 1: Run the complete documentation verification**

```bash
uv run --extra docs mkdocs build --strict --site-dir site
git diff --check main...HEAD
git status --short
```

Expected: the build succeeds, the branch diff has no whitespace errors, and
only the pre-existing `skills-lock.json` and `better-auth/` working-tree changes
remain outside committed branch changes.

- [ ] **Step 2: Review the committed diff**

```bash
git diff --stat main...HEAD
git diff main...HEAD -- mkdocs.yml docs/stylesheets/extra.css
```

Expected: the diff contains only the approved design/plan documentation,
MkDocs configuration, and custom stylesheet.

- [ ] **Step 3: Complete the feature branch**

Use the `superpowers:finishing-a-development-branch` workflow to merge the
verified branch into `main`, push it, monitor the Pages workflow, and verify the
public site.
