# Paper: Dimensional Encryption

## Files

- `dimensional-encryption.tex` — Full LaTeX source
- `Dimensional_Encryption__A_Fault_Tolerant_Cipher_from_Heterogeneous_Pseudorandom_Permutations.pdf` — Compiled PDF

## Compiling

### Option A: Overleaf (recommended — browser-based, free)

1. Go to https://www.overleaf.com
2. New Project → Blank Project
3. Replace `main.tex` with the contents of `dimensional-encryption.tex`
4. Compile

### Option B: Local LaTeX

```bash
cd paper/
pdflatex dimensional-encryption.tex
pdflatex dimensional-encryption.tex  # Run twice for references
```

### Option C: Install LaTeX on macOS

```bash
brew install --cask mactex-no-gui
```
