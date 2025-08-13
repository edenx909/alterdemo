const express = require("express");
const cors = require("cors");
const path = require("path");
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));
app.use("/fonts", express.static("fonts"));

// Enhanced Data Models matching frontend
const identities = [
  {
    id: 'admin-001',
    name: 'Administrator',
    roleType: 'admin',
    status: 'active',
    createdDate: new Date().toISOString().split('T')[0],
    assignedPolicies: ['admin-full-access'],
    customPermissions: {}
  },
  {
    id: 'dev-002',
    name: 'Developer Lead',
    roleType: 'dev',
    status: 'active',
    createdDate: new Date().toISOString().split('T')[0],
    assignedPolicies: ['developer-standard'],
    customPermissions: {}
  },
  {
    id: 'sales-003',
    name: 'Sales Manager',
    roleType: 'sales',
    status: 'active',
    createdDate: new Date().toISOString().split('T')[0],
    assignedPolicies: ['sales-team'],
    customPermissions: {}
  },
  {
    id: 'restricted-004',
    name: 'External Contractor',
    roleType: 'restricted',
    status: 'active',
    createdDate: new Date().toISOString().split('T')[0],
    assignedPolicies: ['external-contractor'],
    customPermissions: {}
  }
];

const policies = [
  {
    id: 'admin-full-access',
    name: 'Admin Full Access',
    description: 'Complete access to all services and tools',
    permissions: {
      'slack.send-message': true,
      'slack.create-channel': true,
      'github.create-issue': true,
      'github.create-pr': true,
      'jira.create-ticket': true,
      'jira.update-status': true,
      'salesforce.create-lead': true,
      'salesforce.update-contact': true
    }
  },
  {
    id: 'developer-standard',
    name: 'Developer Standard',
    description: 'Full GitHub/Jira, limited Slack, no Salesforce',
    permissions: {
      'slack.send-message': true,
      'slack.create-channel': false,
      'github.create-issue': true,
      'github.create-pr': true,
      'jira.create-ticket': true,
      'jira.update-status': true,
      'salesforce.create-lead': false,
      'salesforce.update-contact': false
    }
  },
  {
    id: 'sales-team',
    name: 'Sales Team',
    description: 'Full Salesforce access, limited development tools',
    permissions: {
      'slack.send-message': true,
      'slack.create-channel': true,
      'github.create-issue': false,
      'github.create-pr': false,
      'jira.create-ticket': true,
      'jira.update-status': false,
      'salesforce.create-lead': true,
      'salesforce.update-contact': true
    }
  },
  {
    id: 'external-contractor',
    name: 'External Contractor',
    description: 'Very limited access for external users',
    permissions: {
      'slack.send-message': true,
      'slack.create-channel': false,
      'github.create-issue': false,
      'github.create-pr': false,
      'jira.create-ticket': false,
      'jira.update-status': false,
      'salesforce.create-lead': false,
      'salesforce.update-contact': false
    }
  }
];

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

// Store audit logs in memory for the demo
let auditLogs = [];

// Permission Resolution Logic (matches frontend)
function getEffectivePermissions(identityId) {
  const identity = identities.find(i => i.id === identityId);
  if (!identity) return {};

  let permissions = {};

  // Apply policy permissions
  identity.assignedPolicies.forEach(policyId => {
    const policy = policies.find(p => p.id === policyId);
    if (policy) {
      Object.assign(permissions, policy.permissions);
    }
  });

  // Apply custom overrides
  Object.assign(permissions, identity.customPermissions);

  return permissions;
}

function getPermissionReason(identityId, action) {
  const identity = identities.find(i => i.id === identityId);
  if (!identity) return 'Identity not found';

  // Check custom permissions first
  if (identity.customPermissions.hasOwnProperty(action)) {
    return 'Custom permission override';
  }

  // Check policies
  for (let policyId of identity.assignedPolicies) {
    const policy = policies.find(p => p.id === policyId);
    if (policy && policy.permissions.hasOwnProperty(action)) {
      return `${policy.name} policy → ${action}`;
    }
  }

  return `${identity.roleType} role → ${action}`;
}

function authorize(req, res, next) {
  const identityId = (req.headers.authorization || "").replace("Bearer ", "");
  const identity = identities.find(i => i.id === identityId);
  
  if (!identity) {
    return res.status(401).json({ 
      error: `❌ Unknown identity: ${identityId}`,
      availableIdentities: identities.map(i => i.id)
    });
  }

  if (identity.status !== 'active') {
    return res.status(401).json({ 
      error: `❌ Identity ${identityId} is not active (status: ${identity.status})`
    });
  }

  req.identity = identity;
  next();
}

function auditLog(identityId, action, allowed, reason, timestamp = new Date()) {
  const identity = identities.find(i => i.id === identityId);
  const identityName = identity ? identity.name : identityId;

  const logEntry = {
    id: `log-${Date.now()}`,
    timestamp: timestamp.toISOString(),
    identity: identityId,
    identityName: identityName,
    action: action,
    allowed: allowed,
    reason: reason,
    riskLevel: allowed ? 'low' : 'medium',
    message: `${allowed ? "✅ ALLOWED" : "❌ BLOCKED"} - ${identityName} → ${action} (${reason})`
  };
  
  auditLogs.unshift(logEntry);
  console.log(`[${logEntry.timestamp}] ${logEntry.message}`);

  // Keep only last 100 logs
  if (auditLogs.length > 100) {
    auditLogs = auditLogs.slice(0, 100);
  }

  return logEntry;
}

// Main page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Enhanced MCP endpoint with new permission system
app.post("/mcp", authorize, (req, res) => {
  const { method } = req.body;
  const [service, action] = (method || "").split(".");
  const identity = req.identity;

  // Check if service and action exist
  if (!services[service] || !services[service].methods.includes(action)) {
    return res.status(400).json({
      error: `❌ Invalid service.action: ${method}`,
      availableServices: Object.keys(services).map(s => ({
        service: s,
        methods: services[s].methods
      }))
    });
  }

  // Get effective permissions for this identity
  const permissions = getEffectivePermissions(identity.id);
  const isAllowed = permissions[method] === true;
  const reason = getPermissionReason(identity.id, method);

  // Log the action
  auditLog(identity.id, method, isAllowed, reason);

  if (!isAllowed) {
    return res.status(403).json({
      error: `❌ Access denied: ${identity.name} (${identity.id}) not authorized for ${method}`,
      reason: reason,
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
    identity: {
      id: identity.id,
      name: identity.name,
      roleType: identity.roleType
    },
    action: method,
    reason: reason,
    timestamp: new Date().toISOString(),
  });
});

// API endpoint to get audit logs
app.get("/api/logs", (req, res) => {
  res.json(auditLogs.slice(0, 50)); // Return last 50 logs
});

// API endpoint to get identities (full data for frontend)
app.get("/api/identities", (req, res) => {
  res.json(identities);
});

// API endpoint to get policies
app.get("/api/policies", (req, res) => {
  res.json(policies);
});

// API endpoint to get available services and methods
app.get("/api/services", (req, res) => {
  const formattedServices = Object.keys(services).map((service) => ({
    service,
    methods: services[service].methods,
  }));
  res.json(formattedServices);
});

// API endpoint to test permissions for a specific identity
app.get("/api/permissions/:identityId", (req, res) => {
  const { identityId } = req.params;
  const identity = identities.find(i => i.id === identityId);
  
  if (!identity) {
    return res.status(404).json({ error: `Identity ${identityId} not found` });
  }

  const permissions = getEffectivePermissions(identityId);
  
  res.json({
    identity: {
      id: identity.id,
      name: identity.name,
      roleType: identity.roleType,
      status: identity.status
    },
    effectivePermissions: permissions,
    assignedPolicies: identity.assignedPolicies.map(policyId => {
      const policy = policies.find(p => p.id === policyId);
      return policy ? { id: policy.id, name: policy.name } : null;
    }).filter(Boolean),
    customOverrides: identity.customPermissions
  });
});

// Identity CRUD endpoints
app.post("/api/identities", (req, res) => {
  const { name, roleType, customRole, assignedPolicies = [], status = 'active' } = req.body;
  
  if (!name || !roleType) {
    return res.status(400).json({ error: "Name and roleType are required" });
  }

  const newIdentity = {
    id: `identity-${Date.now()}`,
    name: name,
    roleType: roleType,
    customRole: roleType === 'custom' ? customRole : undefined,
    status: status,
    createdDate: new Date().toISOString().split('T')[0],
    assignedPolicies: assignedPolicies,
    customPermissions: {}
  };

  identities.push(newIdentity);
  auditLog('system', 'create-identity', true, `Identity ${newIdentity.name} created`);
  
  res.json(newIdentity);
});

app.put("/api/identities/:identityId", (req, res) => {
  const { identityId } = req.params;
  const updates = req.body;
  
  const identityIndex = identities.findIndex(i => i.id === identityId);
  if (identityIndex === -1) {
    return res.status(404).json({ error: "Identity not found" });
  }

  identities[identityIndex] = { ...identities[identityIndex], ...updates };
  auditLog('system', 'update-identity', true, `Identity ${identities[identityIndex].name} updated`);
  
  res.json(identities[identityIndex]);
});

app.delete("/api/identities/:identityId", (req, res) => {
  const { identityId } = req.params;
  
  const identityIndex = identities.findIndex(i => i.id === identityId);
  if (identityIndex === -1) {
    return res.status(404).json({ error: "Identity not found" });
  }

  const deletedIdentity = identities.splice(identityIndex, 1)[0];
  auditLog('system', 'delete-identity', true, `Identity ${deletedIdentity.name} deleted`);
  
  res.json({ message: "Identity deleted successfully" });
});

// Policy CRUD endpoints
app.post("/api/policies", (req, res) => {
  const { name, description, permissions } = req.body;
  
  if (!name || !permissions) {
    return res.status(400).json({ error: "Name and permissions are required" });
  }

  const newPolicy = {
    id: `policy-${Date.now()}`,
    name: name,
    description: description || '',
    permissions: permissions
  };

  policies.push(newPolicy);
  auditLog('system', 'create-policy', true, `Policy ${newPolicy.name} created`);
  
  res.json(newPolicy);
});

app.put("/api/policies/:policyId", (req, res) => {
  const { policyId } = req.params;
  const updates = req.body;
  
  const policyIndex = policies.findIndex(p => p.id === policyId);
  if (policyIndex === -1) {
    return res.status(404).json({ error: "Policy not found" });
  }

  policies[policyIndex] = { ...policies[policyIndex], ...updates };
  auditLog('system', 'update-policy', true, `Policy ${policies[policyIndex].name} updated`);
  
  res.json(policies[policyIndex]);
});

app.delete("/api/policies/:policyId", (req, res) => {
  const { policyId } = req.params;
  
  const policyIndex = policies.findIndex(p => p.id === policyId);
  if (policyIndex === -1) {
    return res.status(404).json({ error: "Policy not found" });
  }

  const deletedPolicy = policies.splice(policyIndex, 1)[0];
  auditLog('system', 'delete-policy', true, `Policy ${deletedPolicy.name} deleted`);
  
  res.json({ message: "Policy deleted successfully" });
});

// Permission toggle endpoint
app.post("/api/identities/:identityId/toggle-permission", (req, res) => {
  const { identityId } = req.params;
  const { tool } = req.body;
  
  const identity = identities.find(i => i.id === identityId);
  if (!identity) {
    return res.status(404).json({ error: "Identity not found" });
  }

  const hasPolicy = identity.assignedPolicies.length > 0;
  const policyPermission = getPolicyPermission(identityId, tool);
  const hasCustomOverride = identity.customPermissions.hasOwnProperty(tool);
  const currentCustomValue = identity.customPermissions[tool];

  let newState, reason;

  if (!hasPolicy) {
    // No policy assigned - toggle between denied and allowed only
    if (!hasCustomOverride || currentCustomValue === false) {
      identity.customPermissions[tool] = true;
      newState = 'allowed';
      reason = 'Permission manually set to allowed';
    } else {
      identity.customPermissions[tool] = false;
      newState = 'denied';
      reason = 'Permission manually set to denied';
    }
  } else {
    // Has policy - cycle through: policy default -> denied -> allowed -> back to policy
    if (!hasCustomOverride) {
      identity.customPermissions[tool] = false;
      newState = 'denied';
      reason = 'Permission manually overridden to denied';
    } else if (currentCustomValue === false) {
      identity.customPermissions[tool] = true;
      newState = 'allowed';
      reason = 'Permission manually overridden to allowed';
    } else {
      delete identity.customPermissions[tool];
      newState = policyPermission ? 'allowed' : 'denied';
      reason = 'Permission override removed, reverted to policy default';
    }
  }

  const finalPermissions = getEffectivePermissions(identityId);
  auditLog(identityId, tool, finalPermissions[tool], reason);

  res.json({
    identity: identity,
    tool: tool,
    newState: newState,
    reason: reason,
    effectivePermissions: finalPermissions
  });
});

// Reset all permissions endpoint
app.post("/api/reset-permissions", (req, res) => {
  identities.forEach(identity => {
    identity.customPermissions = {};
  });
  
  auditLog('system', 'reset-permissions', true, 'All custom permissions reset by administrator');
  
  res.json({ message: "All custom permissions have been reset to policy defaults." });
});

// Helper function for policy permissions (moved from frontend logic)
function getPolicyPermission(identityId, tool) {
  const identity = identities.find(i => i.id === identityId);
  if (!identity) return false;

  // Check policies only (ignore custom overrides)
  for (let policyId of identity.assignedPolicies) {
    const policy = policies.find(p => p.id === policyId);
    if (policy && policy.permissions.hasOwnProperty(tool)) {
      return policy.permissions[tool];
    }
  }
  return false;
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`🚀 MCP Gateway running on port ${PORT}`);
  console.log(`\n📋 Available identities for testing:`);
  identities.forEach(identity => {
    console.log(`   - ${identity.id} (${identity.name} - ${identity.roleType})`);
  });
  console.log(`\n💡 Example curl commands:`);
  console.log(`   curl -X POST http://localhost:${PORT}/mcp \\`);
  console.log(`        -H "Content-Type: application/json" \\`);
  console.log(`        -H "Authorization: Bearer admin-001" \\`);
  console.log(`        -d '{"method": "github.create-issue"}'`);
  console.log(`\n   curl -X POST http://localhost:${PORT}/mcp \\`);
  console.log(`        -H "Content-Type: application/json" \\`);
  console.log(`        -H "Authorization: Bearer sales-003" \\`);
  console.log(`        -d '{"method": "github.create-pr"}'`);
});