-- Baseline

CREATE TYPE time_zone AS ENUM (
    'UTC',
    'US/Pacific',
    'US/Mountain',
    'US/Central',
    'US/Eastern'
);

CREATE TYPE invitation_state AS ENUM (
    'pending',
    'cancelled',
    'accepted',
    'rejected'
);

CREATE TYPE oauth2_client_token_scopes AS ENUM (
    'unknown',
    'account_member',
    'account_admin',
    'service_admin'
);

CREATE TYPE setting_type AS ENUM (
    'user',
    'account',
    'membership'
);


CREATE TYPE webhook_event AS ENUM (
    'webhook_created',
    'webhook_updated',
    'webhook_archived'
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT NOT NULL PRIMARY KEY,
    username TEXT NOT NULL,
    avatar_src TEXT,
    email_address TEXT NOT NULL,
    hashed_password TEXT NOT NULL,
    password_last_changed_at TIMESTAMP WITH TIME ZONE,
    requires_password_change BOOLEAN DEFAULT FALSE NOT NULL,
    two_factor_secret TEXT NOT NULL,
    two_factor_secret_verified_at TIMESTAMP WITH TIME ZONE,
    service_role TEXT DEFAULT 'service_user'::TEXT NOT NULL,
    user_account_status TEXT DEFAULT 'unverified'::TEXT NOT NULL,
    user_account_status_explanation TEXT DEFAULT ''::TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    birthday TIMESTAMP WITH TIME ZONE,
    email_address_verification_token TEXT DEFAULT ''::TEXT,
    email_address_verified_at TIMESTAMP WITH TIME ZONE,
    first_name TEXT DEFAULT ''::TEXT NOT NULL,
    last_name TEXT DEFAULT ''::TEXT NOT NULL,
    last_accepted_terms_of_service TIMESTAMP WITH TIME ZONE,
    last_accepted_privacy_policy TIMESTAMP WITH TIME ZONE,
    last_indexed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(username)
);

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    billing_status TEXT DEFAULT 'unpaid'::TEXT NOT NULL,
    contact_phone TEXT DEFAULT ''::TEXT NOT NULL,
    payment_processor_customer_id TEXT DEFAULT ''::TEXT NOT NULL,
    subscription_plan_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE,
    time_zone time_zone DEFAULT 'US/Central'::time_zone NOT NULL,
    address_line_1 TEXT DEFAULT ''::TEXT NOT NULL,
    address_line_2 TEXT DEFAULT ''::TEXT NOT NULL,
    city TEXT DEFAULT ''::TEXT NOT NULL,
    state TEXT DEFAULT ''::TEXT NOT NULL,
    zip_code TEXT DEFAULT ''::TEXT NOT NULL,
    country TEXT DEFAULT ''::TEXT NOT NULL,
    latitude NUMERIC(14,11),
    longitude NUMERIC(14,11),
    last_payment_provider_sync_occurred_at TIMESTAMP WITH TIME ZONE,
    webhook_hmac_secret TEXT DEFAULT ''::TEXT NOT NULL,
    UNIQUE(belongs_to_user, name)
);

CREATE TABLE IF NOT EXISTS account_user_memberships (
    id TEXT NOT NULL PRIMARY KEY,
    belongs_to_account TEXT NOT NULL REFERENCES accounts("id") ON DELETE CASCADE,
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE,
    default_account BOOLEAN DEFAULT FALSE NOT NULL,
    account_role TEXT DEFAULT 'account_user'::TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(belongs_to_account, belongs_to_user)
);

CREATE TABLE IF NOT EXISTS account_invitations (
    id TEXT NOT NULL PRIMARY KEY,
    destination_account TEXT NOT NULL REFERENCES accounts("id") ON DELETE CASCADE,
    to_email TEXT NOT NULL,
    to_user TEXT  REFERENCES users("id") ON DELETE CASCADE,
    from_user TEXT NOT NULL  REFERENCES users("id") ON DELETE CASCADE,
    status invitation_state DEFAULT 'pending'::invitation_state NOT NULL,
    note TEXT DEFAULT ''::TEXT NOT NULL,
    status_note TEXT DEFAULT ''::TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + '7 days'::INTERVAL) NOT NULL,
    to_name TEXT DEFAULT ''::TEXT NOT NULL,
    UNIQUE(to_user, from_user, destination_account)
);

CREATE TABLE IF NOT EXISTS service_settings (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT DEFAULT ''::TEXT NOT NULL,
    type setting_type DEFAULT 'user'::setting_type NOT NULL,
    description TEXT DEFAULT ''::TEXT NOT NULL,
    default_value TEXT,
    enumeration TEXT DEFAULT ''::TEXT NOT NULL,
    admins_only BOOLEAN DEFAULT true NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(name, archived_at)
);

CREATE TABLE IF NOT EXISTS service_setting_configurations (
    id TEXT NOT NULL PRIMARY KEY,
    value TEXT DEFAULT ''::TEXT NOT NULL,
    notes TEXT DEFAULT ''::TEXT NOT NULL,
    service_setting_id TEXT NOT NULL REFERENCES service_settings("id") ON DELETE CASCADE,
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE,
    belongs_to_account TEXT NOT NULL REFERENCES accounts("id") ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(belongs_to_user, belongs_to_account, service_setting_id)
);

CREATE TABLE IF NOT EXISTS oauth2_clients (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT ''::TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    archived_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(client_id),
    UNIQUE(client_secret)
);

CREATE TABLE IF NOT EXISTS oauth2_client_tokens (
    id TEXT NOT NULL PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth2_clients("client_id") ON DELETE CASCADE,
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE,
    redirect_uri TEXT DEFAULT ''::TEXT NOT NULL,
    scope oauth2_client_token_scopes DEFAULT 'unknown'::oauth2_client_token_scopes NOT NULL,
    code TEXT DEFAULT ''::TEXT NOT NULL,
    code_challenge TEXT DEFAULT ''::TEXT NOT NULL,
    code_challenge_method TEXT DEFAULT ''::TEXT NOT NULL,
    code_created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    code_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + '01:00:00'::INTERVAL) NOT NULL,
    access TEXT DEFAULT ''::TEXT NOT NULL,
    access_created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    access_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + '01:00:00'::INTERVAL) NOT NULL,
    refresh TEXT DEFAULT ''::TEXT NOT NULL,
    refresh_created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    refresh_expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + '01:00:00'::INTERVAL) NOT NULL,
    UNIQUE(belongs_to_user, client_id, scope, code_expires_at, access_expires_at, refresh_expires_at)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT NOT NULL PRIMARY KEY,
    token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    redeemed_at TIMESTAMP WITH TIME ZONE,
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    content_type TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMP WITH TIME ZONE,
    archived_at TIMESTAMP WITH TIME ZONE,
    belongs_to_account TEXT NOT NULL REFERENCES accounts("id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webhook_trigger_events (
    id TEXT NOT NULL PRIMARY KEY,
    trigger_event webhook_event NOT NULL,
    belongs_to_webhook TEXT NOT NULL REFERENCES webhooks("id") ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    archived_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(trigger_event, belongs_to_webhook)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    data BYTEA NOT NULL,
    expiry TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(token)
);

CREATE TYPE user_notification_status AS ENUM (
    'unread',
    'read',
    'dismissed'
);
CREATE TYPE audit_log_event_type AS ENUM (
    'other',
    'created',
    'updated',
    'archived'
);

CREATE TABLE IF NOT EXISTS audit_log_entries (
    id TEXT NOT NULL PRIMARY KEY,
    resource_type TEXT NOT NULL,
    relevant_id TEXT NOT NULL DEFAULT '',
    event_type audit_log_event_type NOT NULL DEFAULT 'other',
    changes JSONB NOT NULL,
    belongs_to_account TEXT REFERENCES accounts("id") ON DELETE CASCADE,
    belongs_to_user TEXT REFERENCES users("id") ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);

CREATE TABLE IF NOT EXISTS user_notifications (
    id TEXT NOT NULL PRIMARY KEY,
    content TEXT NOT NULL,
    status user_notification_status NOT NULL DEFAULT 'unread',
    belongs_to_user TEXT NOT NULL REFERENCES users("id") ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    last_updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions USING btree (expiry);
CREATE INDEX IF NOT EXISTS webhook_trigger_events_belongs_to_webhook_index ON webhook_trigger_events USING btree (belongs_to_webhook);
CREATE INDEX IF NOT EXISTS account_invitations_destination_account ON account_invitations USING btree (destination_account);
CREATE INDEX IF NOT EXISTS account_invitations_from_user ON account_invitations USING btree (from_user);
CREATE INDEX IF NOT EXISTS account_invitations_to_user ON account_invitations USING btree (to_user);
CREATE INDEX IF NOT EXISTS account_user_memberships_belongs_to_account ON account_user_memberships USING btree (belongs_to_account);
CREATE INDEX IF NOT EXISTS account_user_memberships_belongs_to_user ON account_user_memberships USING btree (belongs_to_user);
CREATE INDEX IF NOT EXISTS accounts_belongs_to_user ON accounts USING btree (belongs_to_user);
CREATE INDEX IF NOT EXISTS password_reset_token_belongs_to_user ON password_reset_tokens USING btree (belongs_to_user);
