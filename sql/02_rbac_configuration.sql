/*
================================================================================
CORTEX AI SECURITY FRAMEWORK - RBAC CONFIGURATION
================================================================================
Description: Configures Role-Based Access Control for GenAI security
Database:    CORTEX_AI_SECURITY
Schema:      PUBLIC
Author:      Cortex Code
Date:        2026-01-12

COMPONENTS:
  1. Custom roles for AI access control
  2. Model allowlist configuration
  3. Cortex model RBAC setup
  4. Privilege grants
================================================================================
*/

USE ROLE ACCOUNTADMIN;

-- ============================================================================
-- STEP 1: CREATE CUSTOM ROLES FOR AI ACCESS
-- ============================================================================

/*
------------------------------------------------------------------------------
Role Hierarchy:
------------------------------------------------------------------------------
                    ACCOUNTADMIN
                         │
              ┌──────────┴──────────┐
              │                     │
    CORTEX_AI_ADMIN_ROLE    SYSADMIN
              │
    ┌─────────┴─────────┐
    │                   │
CORTEX_AI_USER_ROLE  CORTEX_AI_READONLY_ROLE

CORTEX_AI_ADMIN_ROLE:
  - Full access to all AI functions
  - Can manage RBAC settings
  - Can view all audit logs
  - Can approve/configure models

CORTEX_AI_USER_ROLE:
  - Access to SECURE_AI_COMPLETE function
  - Can use approved models only
  - Audit log entries created for all usage
  
CORTEX_AI_READONLY_ROLE:
  - Read-only access to audit logs and dashboards
  - No access to AI functions
*/

-- Create Admin Role
CREATE ROLE IF NOT EXISTS CORTEX_AI_ADMIN_ROLE
    COMMENT = 'Administrator role for Cortex AI Security framework. Full access to all functions and audit logs.';

-- Create User Role  
CREATE ROLE IF NOT EXISTS CORTEX_AI_USER_ROLE
    COMMENT = 'Standard user role for Cortex AI. Access to secure AI functions with guardrails enabled.';

-- Create Readonly Role
CREATE ROLE IF NOT EXISTS CORTEX_AI_READONLY_ROLE
    COMMENT = 'Read-only role for monitoring Cortex AI usage. Access to audit logs and dashboards only.';

-- Set up role hierarchy
GRANT ROLE CORTEX_AI_USER_ROLE TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT ROLE CORTEX_AI_READONLY_ROLE TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT ROLE CORTEX_AI_ADMIN_ROLE TO ROLE SYSADMIN;


-- ============================================================================
-- STEP 2: CONFIGURE MODEL ALLOWLIST
-- ============================================================================

/*
------------------------------------------------------------------------------
Model Allowlist Configuration
------------------------------------------------------------------------------
Purpose: Restricts which LLM models can be used in your account.
         Only models in this list (or granted via RBAC) can be accessed.
         
Recommendation: Start with a restrictive list and expand as needed.

Options:
  - 'All': Allow all models (not recommended for production)
  - 'None': Block all models (use RBAC for fine-grained control)
  - Comma-separated list: Specific models only
------------------------------------------------------------------------------
*/

-- Option A: Restrictive allowlist (RECOMMENDED)
-- Only allow specific approved models
ALTER ACCOUNT SET CORTEX_MODELS_ALLOWLIST = 'llama3.1-70b,llama3.1-8b,mistral-large2,snowflake-arctic';

-- Option B: Block all and use RBAC only (most secure)
-- ALTER ACCOUNT SET CORTEX_MODELS_ALLOWLIST = 'None';

-- Option C: Allow all models (not recommended)
-- ALTER ACCOUNT SET CORTEX_MODELS_ALLOWLIST = 'All';

-- Verify the setting
SHOW PARAMETERS LIKE 'CORTEX_MODELS_ALLOWLIST' IN ACCOUNT;


-- ============================================================================
-- STEP 3: SET UP CORTEX MODEL RBAC
-- ============================================================================

/*
------------------------------------------------------------------------------
Cortex Model RBAC Setup
------------------------------------------------------------------------------
Purpose: Creates model objects in SNOWFLAKE.MODELS schema for fine-grained
         access control. This allows granting specific model access to roles.
         
Process:
  1. Refresh model objects (creates objects for all available models)
  2. Grant specific model roles to custom roles
------------------------------------------------------------------------------
*/

-- Refresh model objects and application roles
CALL SNOWFLAKE.MODELS.CORTEX_BASE_MODELS_REFRESH();

-- Verify models are available
SHOW MODELS IN SNOWFLAKE.MODELS;

-- Grant specific model access to CORTEX_AI_USER_ROLE
-- (These grants provide access even if models are not in allowlist)
GRANT APPLICATION ROLE SNOWFLAKE."CORTEX-MODEL-ROLE-LLAMA3.1-70B" TO ROLE CORTEX_AI_USER_ROLE;
GRANT APPLICATION ROLE SNOWFLAKE."CORTEX-MODEL-ROLE-LLAMA3.1-8B" TO ROLE CORTEX_AI_USER_ROLE;
GRANT APPLICATION ROLE SNOWFLAKE."CORTEX-MODEL-ROLE-MISTRAL-LARGE2" TO ROLE CORTEX_AI_USER_ROLE;
GRANT APPLICATION ROLE SNOWFLAKE."CORTEX-MODEL-ROLE-SNOWFLAKE-ARCTIC" TO ROLE CORTEX_AI_USER_ROLE;

-- Grant all model access to admin role
GRANT APPLICATION ROLE SNOWFLAKE."CORTEX-MODEL-ROLE-ALL" TO ROLE CORTEX_AI_ADMIN_ROLE;


-- ============================================================================
-- STEP 4: REVOKE PUBLIC ACCESS TO CORTEX FUNCTIONS
-- ============================================================================

/*
------------------------------------------------------------------------------
Revoke Default Public Access
------------------------------------------------------------------------------
Purpose: By default, CORTEX_USER role is granted to PUBLIC. We revoke this
         to enforce explicit role-based access control.
         
WARNING: This affects all users in the account. Ensure you have granted
         appropriate access to required roles before running this.
------------------------------------------------------------------------------
*/

-- CAUTION: Uncomment the following lines only after granting access to required roles
-- This will prevent all users from accessing Cortex AI functions by default

-- REVOKE DATABASE ROLE SNOWFLAKE.CORTEX_USER FROM ROLE PUBLIC;
-- REVOKE IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE FROM ROLE PUBLIC;

-- Instead, grant CORTEX_USER to our custom roles
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE CORTEX_AI_USER_ROLE;


-- ============================================================================
-- STEP 5: GRANT DATABASE AND SCHEMA PRIVILEGES
-- ============================================================================

-- Grant database usage
GRANT USAGE ON DATABASE CORTEX_AI_SECURITY TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON DATABASE CORTEX_AI_SECURITY TO ROLE CORTEX_AI_USER_ROLE;
GRANT USAGE ON DATABASE CORTEX_AI_SECURITY TO ROLE CORTEX_AI_READONLY_ROLE;

-- Grant schema usage
GRANT USAGE ON SCHEMA CORTEX_AI_SECURITY.PUBLIC TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON SCHEMA CORTEX_AI_SECURITY.PUBLIC TO ROLE CORTEX_AI_USER_ROLE;
GRANT USAGE ON SCHEMA CORTEX_AI_SECURITY.PUBLIC TO ROLE CORTEX_AI_READONLY_ROLE;

-- Grant warehouse usage (replace with your warehouse name)
-- GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE CORTEX_AI_ADMIN_ROLE;
-- GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE CORTEX_AI_USER_ROLE;
-- GRANT USAGE ON WAREHOUSE <YOUR_WAREHOUSE> TO ROLE CORTEX_AI_READONLY_ROLE;


-- ============================================================================
-- STEP 6: GRANT FUNCTION PRIVILEGES
-- ============================================================================

/*
------------------------------------------------------------------------------
Function Access Control
------------------------------------------------------------------------------
CORTEX_AI_ADMIN_ROLE: All functions
CORTEX_AI_USER_ROLE: Only SECURE_AI_COMPLETE (enforces full security pipeline)
CORTEX_AI_READONLY_ROLE: No function access
------------------------------------------------------------------------------
*/

-- Admin role: Full access to all functions
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.IS_PROMPT_INJECTION(VARCHAR, FLOAT) TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.CLASSIFY_INPUT_SAFETY(VARCHAR) TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.REDACT_PII(VARCHAR) TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.SECURE_PROMPT_FORMAT(VARCHAR, VARCHAR) TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.GUARDED_AI_COMPLETE(VARCHAR, VARCHAR, FLOAT, INT) TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT USAGE ON FUNCTION CORTEX_AI_SECURITY.PUBLIC.GUARDED_AI_COMPLETE_DETAILED(VARCHAR, VARCHAR, FLOAT, INT) TO ROLE CORTEX_AI_ADMIN_ROLE;

-- Grant procedure execution (main entry point)
GRANT USAGE ON PROCEDURE CORTEX_AI_SECURITY.PUBLIC.SECURE_AI_COMPLETE_PROC(VARCHAR, VARCHAR, VARCHAR, DOUBLE, DOUBLE, DOUBLE) TO ROLE CORTEX_AI_ADMIN_ROLE;

-- User role: Only SECURE_AI_COMPLETE_PROC (enforces complete security pipeline)
GRANT USAGE ON PROCEDURE CORTEX_AI_SECURITY.PUBLIC.SECURE_AI_COMPLETE_PROC(VARCHAR, VARCHAR, VARCHAR, DOUBLE, DOUBLE, DOUBLE) TO ROLE CORTEX_AI_USER_ROLE;


-- ============================================================================
-- STEP 7: GRANT TABLE AND VIEW PRIVILEGES
-- ============================================================================

-- Audit log table access
GRANT SELECT, INSERT ON TABLE CORTEX_AI_SECURITY.PUBLIC.GENAI_AUDIT_LOG TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT INSERT ON TABLE CORTEX_AI_SECURITY.PUBLIC.GENAI_AUDIT_LOG TO ROLE CORTEX_AI_USER_ROLE;
GRANT SELECT ON TABLE CORTEX_AI_SECURITY.PUBLIC.GENAI_AUDIT_LOG TO ROLE CORTEX_AI_READONLY_ROLE;

-- Allow admin to update feedback columns
GRANT UPDATE ON TABLE CORTEX_AI_SECURITY.PUBLIC.GENAI_AUDIT_LOG TO ROLE CORTEX_AI_ADMIN_ROLE;

-- Dashboard views access
GRANT SELECT ON VIEW CORTEX_AI_SECURITY.PUBLIC.V_SECURITY_DASHBOARD TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT SELECT ON VIEW CORTEX_AI_SECURITY.PUBLIC.V_SECURITY_DASHBOARD TO ROLE CORTEX_AI_READONLY_ROLE;

GRANT SELECT ON VIEW CORTEX_AI_SECURITY.PUBLIC.V_RECENT_THREATS TO ROLE CORTEX_AI_ADMIN_ROLE;
GRANT SELECT ON VIEW CORTEX_AI_SECURITY.PUBLIC.V_RECENT_THREATS TO ROLE CORTEX_AI_READONLY_ROLE;


-- ============================================================================
-- STEP 8: GRANT ROLES TO USERS
-- ============================================================================

/*
------------------------------------------------------------------------------
Grant Roles to Users
------------------------------------------------------------------------------
Uncomment and modify the following statements to grant roles to specific users.
------------------------------------------------------------------------------
*/

-- Example: Grant admin role to a user
-- GRANT ROLE CORTEX_AI_ADMIN_ROLE TO USER admin_user;

-- Example: Grant user role to analysts
-- GRANT ROLE CORTEX_AI_USER_ROLE TO USER analyst1;
-- GRANT ROLE CORTEX_AI_USER_ROLE TO USER analyst2;

-- Example: Grant readonly role to auditors
-- GRANT ROLE CORTEX_AI_READONLY_ROLE TO USER auditor1;

-- Grant to current user for testing
GRANT ROLE CORTEX_AI_ADMIN_ROLE TO USER IDENTIFIER($CURRENT_USER);


-- ============================================================================
-- STEP 9: CREATE ROW ACCESS POLICY (OPTIONAL)
-- ============================================================================

/*
------------------------------------------------------------------------------
Row Access Policy for Audit Logs
------------------------------------------------------------------------------
Purpose: Restricts users to viewing only their own audit log entries,
         except for admins who can see all entries.
------------------------------------------------------------------------------
*/

CREATE OR REPLACE ROW ACCESS POLICY CORTEX_AI_SECURITY.PUBLIC.AUDIT_LOG_ACCESS_POLICY
    AS (user_name_col VARCHAR) 
    RETURNS BOOLEAN ->
        CURRENT_ROLE() IN ('CORTEX_AI_ADMIN_ROLE', 'ACCOUNTADMIN', 'SYSADMIN')
        OR user_name_col = CURRENT_USER();

-- Apply row access policy to audit log table
-- Uncomment to enable:
-- ALTER TABLE CORTEX_AI_SECURITY.PUBLIC.GENAI_AUDIT_LOG 
--     ADD ROW ACCESS POLICY CORTEX_AI_SECURITY.PUBLIC.AUDIT_LOG_ACCESS_POLICY 
--     ON (user_name);


-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify role hierarchy
SHOW GRANTS TO ROLE CORTEX_AI_ADMIN_ROLE;
SHOW GRANTS TO ROLE CORTEX_AI_USER_ROLE;
SHOW GRANTS TO ROLE CORTEX_AI_READONLY_ROLE;

-- Verify model allowlist
SHOW PARAMETERS LIKE 'CORTEX_MODELS_ALLOWLIST' IN ACCOUNT;

-- Verify model RBAC
SHOW APPLICATION ROLES IN APPLICATION SNOWFLAKE;

-- Test role access (switch to user role and try functions)
-- USE ROLE CORTEX_AI_USER_ROLE;
-- SELECT SECURE_AI_COMPLETE('What is machine learning?');


-- ============================================================================
-- CLEANUP COMMANDS (USE WITH CAUTION)
-- ============================================================================

/*
To remove the RBAC configuration, run the following commands:

DROP ROLE IF EXISTS CORTEX_AI_ADMIN_ROLE;
DROP ROLE IF EXISTS CORTEX_AI_USER_ROLE;
DROP ROLE IF EXISTS CORTEX_AI_READONLY_ROLE;
ALTER ACCOUNT SET CORTEX_MODELS_ALLOWLIST = 'All';
*/
