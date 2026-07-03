const mysql = require("mysql");

function getUser(db, userId) {
  // Intentionally vulnerable: string-concatenated SQL query (SQLi).
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

function runUserScript(userInput) {
  // Intentionally vulnerable: eval on untrusted input.
  return eval(userInput);
}

module.exports = { getUser, runUserScript };
