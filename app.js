/**
 * app.js
 *
 * Combines a background process that scans TCP/UDP connections and blocks IPs,
 * with an Express web interface using EJS for templating.
 */

const express = require("express");
const bodyParser = require("body-parser");
const { promisify } = require("util");
const { exec } = require("child_process");
const dns = require("dns");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const cidrMatcher = require("cidr-matcher");
const { readFile } = require("fs/promises");
const path = require("path");
const netstat = require("node-netstat");

// Promisify built-ins
const execPromise = promisify(exec);
const reverseDns = promisify(dns.reverse);
// const lookup = promisify(dns.lookup);

const bloackingIpList = {};

async function getAwsIpRanges() {
  // Adjust the file path as needed.
  const filePath = path.join(process.cwd(), "db/ip-ranges.json");
  const fileData = await readFile(filePath, "utf-8");
  const data = JSON.parse(fileData);
  // Return an array of IP prefixes.
  return data.prefixes.map((prefix) => prefix.ip_prefix);
}

// Check if an IP is within any AWS CIDR range.
async function isAwsS3Ip(ip) {
  const ranges = await getAwsIpRanges();
  // Create a matcher instance directly.
  const matcher = new cidrMatcher(ranges);
  return matcher.contains(ip);
}
// Set refresh interval in milliseconds
const REFRESH_INTERVAL = 2000;

// Setup lowdb (database stored in db.json)
const adapter = new FileSync("db/db.json");
const db = low(adapter);
db.defaults({
  blockRules: [],
  blockingStrings: ["s3", "aws.amazon.com"],
}).write();

// --------------------
// Helper Functions
// --------------------

// Check if a firewall rule exists.
async function ruleExists(ruleName) {
  try {
    const { stdout } = await execPromise(
      `netsh advfirewall firewall show rule name="${ruleName}"`
    );
    return !stdout.includes("No rules match");
  } catch {
    return false;
  }
}

// Block an IP using Windows Firewall (if not already blocked).
async function blockIp(ip, blockString, connectionDetail) {
  const ruleName = `Block_IP_${ip}`;
  if (bloackingIpList[ip] || (await ruleExists(ruleName))) return;
  try {
    bloackingIpList[ip] = 1;
    const cmd = `netsh advfirewall firewall add rule name="${ruleName}" dir=out remoteip=${ip} action=block`;
    await execPromise(cmd);
    db.get("blockRules")
      .push({
        ip,
        ruleName,
        blockString,
        connectionDetail,
        timestamp: Date.now(),
      })
      .write();
    delete bloackingIpList[ip];
  } catch (err) {
    // Handle error appropriately.
  }
}

// Remove a firewall rule by rule name.
async function unblockIp(ip) {
  const ruleName = `Block_IP_${ip}`;
  if (!(await ruleExists(ruleName))) return;
  try {
    const cmd = `netsh advfirewall firewall delete rule name="${ruleName}"`;
    await execPromise(cmd);
    db.get("blockRules").remove({ ruleName }).write();
  } catch (err) {
    // Handle error appropriately.
  }
}

// Remove all firewall rules associated with a given block string.
async function unblockByBlockString(blockString) {
  const rules = db.get("blockRules").filter({ blockString }).value();
  for (const rule of rules) {
    await unblockIp(rule.ip);
  }
}

// In-memory cache for PID -> process name
const processCache = {};

/**
 * Retrieves the process name for a given PID using tasklist.
 * Returns null if the process is not found or if an error occurs.
 *
 * @param {number|string} pid - The PID to look up.
 * @returns {Promise<string|null>} - The process name or null.
 */
async function getProcessNameByPid(pid) {
  // Skip PID 0 since it's not a real process.
  if (parseInt(pid) === 0) return null;
  // Check cache first.
  if (processCache[pid]) return processCache[pid];

  try {
    const { stdout } = await execPromise(
      `tasklist /FI "PID eq ${pid}" /FO CSV`
    );
    const lines = stdout.trim().split("\n");
    if (lines.length < 2) {
      processCache[pid] = null;
      return null; // No matching process found.
    }
    // CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
    const fields = lines[1]
      .split(",")
      .map((field) => field.replace(/"/g, "").trim());
    const processName = fields[0];
    processCache[pid] = processName;
    return processName;
  } catch (err) {
    // Log the error if desired, or silently ignore.
    console.error(`Error getting process name for PID ${pid}:`, err.message);
    processCache[pid] = null; // Cache as null to prevent repeated calls.
    return null;
  }
}

async function getAwsIpRanges() {
  // Adjust the file path as needed.
  const filePath = path.join(process.cwd(), "db/ip-ranges.json");
  const fileData = await readFile(filePath, "utf-8");
  const data = JSON.parse(fileData);
  // Return an array of IP prefixes.
  return data.prefixes.map((prefix) => prefix.ip_prefix);
}

// Check if an IP is within any AWS CIDR range.
async function isAwsS3Ip(ip) {
  const ranges = await getAwsIpRanges();
  // Create a matcher instance directly.
  const matcher = new cidrMatcher(ranges);
  return matcher.contains(ip);
}

async function resolveRemoteAddress(conn) {
  if (!conn.remote || !conn.remote.address) return conn;
  if (
    ["0.0.0.0", "127.0.0.1", "::", "::1"].includes(conn.remote.address) ||
    conn.remote.address.startsWith("fe80")
  ) {
    return conn;
  }
  try {
    const hostnames = await reverseDns(conn.remote.address);
    if (hostnames && hostnames.length > 0) {
      conn.remote.address = hostnames[0];
    } else if (await isAwsS3Ip(conn.remote.address)) {
      conn.remote.address = "aws.amazon.com";
    }
  } catch {
    // Leave as IP if reverse DNS fails.
    if (await isAwsS3Ip(conn.remote.address)) {
      conn.remote.address = "aws.amazon.com";
    }
  }
  return conn;
}

setInterval(() => {
  netstat(
    {
      filter: {
        protocol: "tcp",
        // state: "ESTABLISHED",
      },
    },
    async function (item) {
      if (item.pid) {
        getProcessNameByPid(item.pid)
          .then((name) => {
            if (name && name.toLowerCase().includes("cursor")) {
              // Preserve the original remote address in a new property.
              item.remote.ip = item.remote?.address;
              if (
                item.remote?.address &&
                !(
                  ["0.0.0.0", "127.0.0.1", "::", "::1"].includes(
                    item.remote.address
                  ) || item.remote.address.startsWith("fe80")
                )
              ) {
                resolveRemoteAddress(item)
                  .then((conn) => {
                    const blockingStrings = db.get("blockingStrings").value();
                    for (const str of blockingStrings) {
                      if (conn.remote?.address.includes(str)) {
                        //  blocking
                        blockIp(item.remote.ip, str, conn).then(() => {});
                      } else {
                        //  non blocking
                      }
                    }
                  })
                  .catch((ex) =>
                    console.log("Error in resolveRemoteAddress:", ex)
                  );
              }
            }
          })
          .catch((e) => console.log("Error in getProcessNameByPid:", e));
      }
    }
  );
}, 2000);
// --------------------
// Express Web Server Setup
// --------------------
const app = express();
app.use(bodyParser.json());
app.set("view engine", "ejs"); // Use EJS as the template engine
app.engine("ejs", require("ejs").__express);
app.set("views", path.join(process.cwd(), "views")); // Set views folder

// Home route: render the index page using EJS.
app.get("/", (req, res) => {
  // Get current block rules and blocking strings from the database.
  const blockRules = db.get("blockRules").value();
  const blockingStrings = db.get("blockingStrings").value();
  res.render("index", { blockRules, blockingStrings });
});

// API endpoint: List block rules.
app.get("/api/blocklist", (req, res) => {
  const blockRules = db.get("blockRules").value();
  res.json(blockRules);
});

// API endpoint: Unblock a rule by ruleName.
app.post("/api/unblock", async (req, res) => {
  const { ruleName } = req.body;
  if (!ruleName) return res.status(400).json({ error: "Missing ruleName" });
  const rule = db.get("blockRules").find({ ruleName }).value();
  if (!rule) return res.status(404).json({ error: "Rule not found" });
  await unblockIp(rule.ip);
  res.json({ success: true });
});

// API endpoint: Get blocking strings.
app.get("/api/blockings", (req, res) => {
  const blockings = db.get("blockingStrings").value();
  res.json(blockings);
});

// API endpoint: Add a blocking string.
app.post("/api/blockings", (req, res) => {
  const { blockStr } = req.body;
  if (!blockStr) return res.status(400).json({ error: "Missing blockStr" });
  const exists = db
    .get("blockingStrings")
    .find((b) => b === blockStr)
    .value();
  if (exists)
    return res.status(400).json({ error: "Blocking string already exists" });
  db.get("blockingStrings").push(blockStr).write();
  res.json({ success: true });
});

// API endpoint: Delete a blocking string and associated firewall rules.
app.delete("/api/blockings/:blockStr", async (req, res) => {
  const blockStr = req.params.blockStr;
  db.get("blockingStrings")
    .remove((b) => b === blockStr)
    .write();
  await unblockByBlockString(blockStr);
  res.json({ success: true });
});

// Start the Express server.
app.listen(3000, async () => {
  // Server is running on port 3000.
  console.log("Server is running on port http://localhost:3000");
});
