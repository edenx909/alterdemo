# MCP Gateway Auth Control - API Documentation

## Overview
This document describes the REST API endpoints expected by the MCP Gateway Auth Control frontend application. All endpoints return JSON data and expect JSON request bodies where applicable.

## Base URL
All endpoints are relative to the application root: `/api/`

---

## Identities Management

### Get All Identities
```http
GET /api/identities
```
**Description**: Retrieve all identities in the system.

**Response**: Array of Identity objects
```json
[
  {
    "id": "string",
    "name": "string",
    "roleType": "admin|dev|sales|restricted|custom",
    "customRole": "string", // optional, if roleType is "custom"
    "status": "active|inactive|suspended", 
    "assignedPolicies": ["policyId1", "policyId2"],
    "customPermissions": {
      "slack.send-message": true,
      "github.create-issue": false
      // ... other permission overrides
    },
    "createdDate": "2024-01-15"
  }
]
```

### Create Identity
```http
POST /api/identities
```
**Description**: Create a new identity.

**Request Body**:
```json
{
  "name": "string",
  "roleType": "admin|dev|sales|restricted|custom",
  "customRole": "string", // required if roleType is "custom"
  "assignedPolicies": ["policyId1"],
  "status": "active|inactive|suspended"
}
```

**Response**: Created Identity object

### Update Identity
```http
PUT /api/identities/{id}
```
**Description**: Update an existing identity.

**Parameters**:
- `id` (path): Identity ID

**Request Body**: Same as Create Identity

**Response**: Updated Identity object

### Delete Identity
```http
DELETE /api/identities/{id}
```
**Description**: Delete an identity.

**Parameters**:
- `id` (path): Identity ID

**Response**: Success confirmation

### Toggle Permission
```http
POST /api/identities/{id}/toggle-permission
```
**Description**: Toggle a specific permission for an identity (creates custom override).

**Parameters**:
- `id` (path): Identity ID

**Request Body**:
```json
{
  "tool": "slack.send-message"
}
```

**Response**: Success confirmation

---

## Policies Management

### Get All Policies
```http
GET /api/policies
```
**Description**: Retrieve all policies in the system.

**Response**: Array of Policy objects
```json
[
  {
    "id": "string",
    "name": "Developer Standard",
    "description": "Standard permissions for developers",
    "permissions": {
      "slack.send-message": true,
      "slack.create-channel": false,
      "salesforce.create-lead": false,
      "salesforce.update-contact": false,
      "github.create-issue": true,
      "github.create-pr": true,
      "jira.create-ticket": true,
      "jira.update-status": true
    }
  }
]
```

### Create Policy
```http
POST /api/policies
```
**Description**: Create a new policy.

**Request Body**:
```json
{
  "name": "string",
  "description": "string",
  "permissions": {
    "slack.send-message": true,
    "slack.create-channel": false,
    "salesforce.create-lead": true,
    "salesforce.update-contact": false,
    "github.create-issue": true,
    "github.create-pr": false,
    "jira.create-ticket": true,
    "jira.update-status": false
  }
}
```

**Response**: Created Policy object

### Update Policy
```http
PUT /api/policies/{id}
```
**Description**: Update an existing policy.

**Parameters**:
- `id` (path): Policy ID

**Request Body**: Same as Create Policy

**Response**: Updated Policy object

### Delete Policy
```http
DELETE /api/policies/{id}
```
**Description**: Delete a policy.

**Parameters**:
- `id` (path): Policy ID

**Response**: Success confirmation

---

## Audit Logs

### Get All Logs
```http
GET /api/logs
```
**Description**: Retrieve all audit logs.

**Response**: Array of Audit Log objects
```json
[
  {
    "id": "log-1641234567890",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "identity": "identityId",
    "action": "slack.send-message",
    "allowed": true,
    "reason": "Developer Standard policy → slack.send-message",
    "riskLevel": "low|medium|high",
    "isTestAction": true
  }
]
```

---

## System Operations

### Reset All Permissions
```http
POST /api/reset-permissions
```
**Description**: Reset all custom permission overrides, reverting to policy-based permissions only.

**Request Body**: Empty `{}`

**Response**:
```json
{
  "message": "All custom permissions have been reset successfully."
}
```

---

## Available Permissions

The system recognizes these permission keys:

### Slack
- `slack.send-message` - Send messages to Slack channels
- `slack.create-channel` - Create new Slack channels

### Salesforce  
- `salesforce.create-lead` - Create new leads in Salesforce
- `salesforce.update-contact` - Update existing contacts

### GitHub
- `github.create-issue` - Create new GitHub issues
- `github.create-pr` - Create pull requests

### Jira
- `jira.create-ticket` - Create new Jira tickets
- `jira.update-status` - Update ticket status

---

## Error Handling

All endpoints should handle errors gracefully and return appropriate HTTP status codes:

- `200` - Success
- `201` - Created 
- `400` - Bad Request
- `404` - Not Found
- `500` - Internal Server Error

Error responses should follow this format:
```json
{
  "error": "Error message describing what went wrong"
}
```

---

## Notes

1. **Permission Logic**: Identities inherit permissions from assigned policies. Custom permissions override policy permissions.

2. **Frontend Behavior**: The frontend calls these endpoints automatically and expects specific data structures. Any deviation may cause UI issues.

3. **Real-time Updates**: After successful API calls, the frontend reloads data from the server to stay in sync.

4. **Test Actions**: When testing permissions in the UI, audit logs are created with `isTestAction: true` to distinguish them from real system actions.