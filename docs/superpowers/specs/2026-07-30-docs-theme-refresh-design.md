# Documentation Theme Refresh

## Goal

Give the fastauth documentation a recognizable but restrained visual identity
and restore syntax highlighting for Python examples. The site will continue to
use MkDocs Material and remain easy to maintain.

## Scope

The refresh will:

- enable Pygments-backed highlighting for fenced and inline code;
- use a deep teal primary color and warm amber accent in light and dark modes;
- add a small stylesheet for typography, link, header, and code-block details;
- preserve the existing navigation, page structure, search, and generated API
  reference;
- retain code-copy and annotation support.

The refresh will not add custom templates, JavaScript, external fonts, a custom
landing-page layout, or new documentation content.

## Configuration

`mkdocs.yml` will enable:

- `pymdownx.highlight` with anchors for line-level links;
- `pymdownx.inlinehilite` for highlighted inline snippets;
- `pymdownx.superfences` for correctly rendered fenced blocks;
- `attr_list` for lightweight Markdown attributes where needed.

The Material palettes will define teal as the primary color and amber as the
accent for both the default and slate schemes. The existing light/dark palette
switching behavior and navigation features will remain intact.

The theme will load `stylesheets/extra.css` through `extra_css`.

## Visual Treatment

The custom stylesheet will use Material's CSS variables and narrowly scoped
selectors so upstream theme behavior remains intact.

- The top navigation will use the deep teal brand color with a thin amber
  bottom accent.
- Links and focus states will use the brand palette with accessible contrast.
- Headings will receive modest weight and spacing adjustments.
- Code blocks will have a subtle branded border and clearer separation from
  surrounding prose.
- Light and dark modes will each define appropriate surface and border colors.

No element will depend on decorative motion, background imagery, or remote
assets.

## Syntax Highlighting

Existing fenced blocks already declare languages such as `python` and `bash`.
Once the Markdown extensions are enabled, MkDocs Material will render Pygments
token classes and apply its built-in light/dark syntax themes.

Representative Python examples must visibly distinguish keywords, strings,
names, comments, and literals. Copy buttons, annotations, optional code-block
titles, and line highlighting must continue to work.

## Validation

Validation will include:

1. `mkdocs build --strict` using the documentation dependency group.
2. Inspection of generated HTML for Pygments token markup on a Python example.
3. A check that the custom stylesheet is present in the generated site.
4. Visual inspection of representative pages in light and dark modes at desktop
   and narrow widths.
5. Confirmation that navigation, search, code copy, and the public canonical URL
   remain functional.

## Delivery

The changes will be developed on the `codex/docs-theme-refresh` feature branch.
After validation, the branch will be merged into `main` and pushed. The existing
GitHub Pages workflow will then build and deploy the refreshed site.
