#!/usr/bin/env node
const {CryptoSolver} = require("../solver/index.js");

const input = process.argv[2];
if (!input) {
  console.log("Usage: solve <ciphertext>");
  process.exit(1);
}

const solver = new CryptoSolver({debug:true});
const result = solver.solve(input);
console.log(JSON.stringify(result, null, 2));