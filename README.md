# Crypto CTF Solver

Production-ready cryptography solver for CTF competitions with LLM training dataset.

## Installation

```bash
npm install
```

## Usage

### CLI
```bash
node src/cli/solve.js "SGVsbG8gV29ybGQ="
```

### Module
```javascript
const {CryptoSolver} = require("./src/solver/index.js");
const solver = new CryptoSolver();
const result = solver.solve("48656c6c6f");
```

## Training Data

See `knowledge/` for attack techniques and `data/processed/` for 68+ CTF challenges.

## Dataset

- `data/processed/challenges.json` — 68 categorized challenges
- `data/processed/training_prompts.jsonl` — LLM training prompts
- `knowledge/attack_techniques.md` — Attack taxonomy

## Structure

```
crypto-ctf-solver/
├── src/
│   └── solver/index.js     # Main solver
├── tests/run.js            # Tests
├── data/processed/         # Training data
├── knowledge/              # Attack techniques
└── package.json
```