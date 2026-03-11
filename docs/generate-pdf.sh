#!/bin/bash
# Generate CBOM Proposal PDF from Markdown
# Requires: pandoc, pdflatex (texlive), xelatex (for Unicode chars)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cd "$SCRIPT_DIR"

pandoc CBOM_PROPOSAL_FOR_DT.md \
  -o ../CBOM_PROPOSAL_FOR_DT.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=0.7in \
  -V linestretch=1.25 \
  -V monofont="DejaVu Sans Mono" \
  -H <(echo '\usepackage{graphicx}')

echo "Generated: CBOM_PROPOSAL_FOR_DT.pdf"
