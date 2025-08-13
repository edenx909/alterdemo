const express = require("express");
const cors = require("cors");
const path = require("path");
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const services = {
  slack: {
    methods: ["send-message", "create-channel"],
    responses: {
      "send-message": "✅ Message sent to #general",
      "create-channel": "✅ Channel #new-project created",
    },
  },
  salesforce: {
    methods: ["create-lead", "update-contact"],
    responses: {
      "create-lead": "✅ Lead created: John Doe",
      "update-contact": "✅ Contact updated",
    },
  },
  github: {
    methods: ["create-issue", "create-pr"],
    responses: {
      "create-issue": "✅ Issue #42 created",
      "create-pr": "✅ PR #15 opened",
    },
  },
  jira: {
    methods: ["create-ticket", "update-status"],
    responses: {
      "create-ticket": "✅ Ticket DEMO-123 created",
      "update-status": "✅ Ticket moved to In Progress",
    },
  },
};

const policies = {
  "demo-user-admin": {
    slack: ["send-message", "create-channel"],
    salesforce: ["create-lead", "update-contact"],
    github: ["create-issue", "create-pr"],
    jira: ["create-ticket", "update-status"],
  },
  "demo-user-dev": {
    slack: ["send-message"],
    salesforce: [],
    github: ["create-issue", "create-pr"],
    jira: ["create-ticket", "update-status"],
  },
  "demo-user-sales": {
    slack: ["send-message"],
    salesforce: ["create-lead", "update-contact"],
    github: [],
    jira: ["create-ticket"],
  },
  "demo-user-restricted": {
    slack: ["send-message"],
    salesforce: [],
    github: [],
    jira: [],
  },
};

// Store audit logs in memory for the demo
let auditLogs = [];

function authorize(req, res, next) {
  const user = (req.headers.authorization || "").replace("Bearer ", "");
  if (!policies[user])
    return res
      .status(401)
      .json({ error: `❌ Unknown or unauthorized user: ${user}` });
  req.user = user;
  next();
}

function auditLog(user, service, method, allowed, timestamp = new Date()) {
  const logEntry = {
    timestamp: timestamp.toISOString(),
    user,
    service,
    method,
    allowed,
    message: `${
      allowed ? "✅ ALLOWED" : "❌ BLOCKED"
    } - User: ${user} | Action: ${service}.${method}`,
  };
  auditLogs.push(logEntry);
  console.log(`[${logEntry.timestamp}] ${logEntry.message}`);

  // Keep only last 100 logs
  if (auditLogs.length > 100) {
    auditLogs = auditLogs.slice(-100);
  }
}

// Main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// API endpoint for MCP requests
app.post("/mcp", authorize, (req, res) => {
  const { method } = req.body;
  const [service, action] = (method || "").split(".");
  const userPolicy = policies[req.user] || {};
  const isAllowed = (userPolicy[service] || []).includes(action);

  auditLog(req.user, service, action, isAllowed);

  if (!isAllowed) {
    return res.status(403).json({
      error: `❌ Access denied: ${req.user} not authorized for ${service}.${action}`,
      timestamp: new Date().toISOString(),
    });
  }

  res.json({
    result: {
      content: [
        {
          type: "text",
          text: services[service].responses[action],
        },
      ],
    },
    timestamp: new Date().toISOString(),
  });
});

// API endpoint to get audit logs
app.get("/api/logs", (req, res) => {
  res.json(auditLogs.slice(-50)); // Return last 50 logs
});

// API endpoint to get user policies for the UI
app.get("/api/policies", (req, res) => {
  const formattedPolicies = Object.keys(policies).map((user) => ({
    user,
    displayName: user.replace("demo-user-", "").toUpperCase(),
    permissions: policies[user],
  }));
  res.json(formattedPolicies);
});

// API endpoint to get available services and methods
app.get("/api/services", (req, res) => {
  const formattedServices = Object.keys(services).map((service) => ({
    service,
    methods: services[service].methods,
  }));
  res.json(formattedServices);
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 MCP Gateway running on port ${PORT}`));
