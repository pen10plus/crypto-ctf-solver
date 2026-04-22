const {CryptoSolver} = require("../src/solver/index.js");
const solver = new CryptoSolver();

const tests = [
  "SGVsbG8gV29ybGQ=",
  "48656c6c6f",
  "5a4147444c5a47584e4e5157545751",
  "d41d8cd98f00b204e9800998ecf8427e"
];

tests.forEach((t,i) => {
  console.log(`Test ${i+1}: ${t}`);
  console.log(JSON.stringify(solver.solve(t), null, 2));
  console.log("---");
});