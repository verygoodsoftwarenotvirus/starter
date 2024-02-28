// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: oauth2_client_tokens.sql

package generated

import (
	"context"
	"time"
)

const archiveOAuth2ClientTokenByAccess = `-- name: ArchiveOAuth2ClientTokenByAccess :execrows

DELETE FROM oauth2_client_tokens WHERE access = $1
`

func (q *Queries) ArchiveOAuth2ClientTokenByAccess(ctx context.Context, db DBTX, access string) (int64, error) {
	result, err := db.ExecContext(ctx, archiveOAuth2ClientTokenByAccess, access)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

const archiveOAuth2ClientTokenByCode = `-- name: ArchiveOAuth2ClientTokenByCode :execrows

DELETE FROM oauth2_client_tokens WHERE code = $1
`

func (q *Queries) ArchiveOAuth2ClientTokenByCode(ctx context.Context, db DBTX, code string) (int64, error) {
	result, err := db.ExecContext(ctx, archiveOAuth2ClientTokenByCode, code)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

const archiveOAuth2ClientTokenByRefresh = `-- name: ArchiveOAuth2ClientTokenByRefresh :execrows

DELETE FROM oauth2_client_tokens WHERE refresh = $1
`

func (q *Queries) ArchiveOAuth2ClientTokenByRefresh(ctx context.Context, db DBTX, refresh string) (int64, error) {
	result, err := db.ExecContext(ctx, archiveOAuth2ClientTokenByRefresh, refresh)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

const checkOAuth2ClientTokenExistence = `-- name: CheckOAuth2ClientTokenExistence :one

SELECT EXISTS (
	SELECT oauth2_client_tokens.id
	FROM oauth2_client_tokens
	WHERE oauth2_client_tokens.archived_at IS NULL
		AND oauth2_client_tokens.id = $1
)
`

func (q *Queries) CheckOAuth2ClientTokenExistence(ctx context.Context, db DBTX, id string) (bool, error) {
	row := db.QueryRowContext(ctx, checkOAuth2ClientTokenExistence, id)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const createOAuth2ClientToken = `-- name: CreateOAuth2ClientToken :exec

INSERT INTO oauth2_client_tokens (
	id,
	client_id,
	belongs_to_user,
	redirect_uri,
	scope,
	code,
	code_challenge,
	code_challenge_method,
	code_created_at,
	code_expires_at,
	access,
	access_created_at,
	access_expires_at,
	refresh,
	refresh_created_at,
	refresh_expires_at
) VALUES (
	$1,
	$2,
	$3,
	$4,
	$5,
	$6,
	$7,
	$8,
	$9,
	$10,
	$11,
	$12,
	$13,
	$14,
	$15,
	$16
)
`

type CreateOAuth2ClientTokenParams struct {
	AccessExpiresAt     time.Time
	CodeExpiresAt       time.Time
	RefreshExpiresAt    time.Time
	RefreshCreatedAt    time.Time
	CodeCreatedAt       time.Time
	AccessCreatedAt     time.Time
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               Oauth2ClientTokenScopes
	ClientID            string
	Access              string
	Code                string
	ID                  string
	Refresh             string
	RedirectUri         string
	BelongsToUser       string
}

func (q *Queries) CreateOAuth2ClientToken(ctx context.Context, db DBTX, arg *CreateOAuth2ClientTokenParams) error {
	_, err := db.ExecContext(ctx, createOAuth2ClientToken,
		arg.ID,
		arg.ClientID,
		arg.BelongsToUser,
		arg.RedirectUri,
		arg.Scope,
		arg.Code,
		arg.CodeChallenge,
		arg.CodeChallengeMethod,
		arg.CodeCreatedAt,
		arg.CodeExpiresAt,
		arg.Access,
		arg.AccessCreatedAt,
		arg.AccessExpiresAt,
		arg.Refresh,
		arg.RefreshCreatedAt,
		arg.RefreshExpiresAt,
	)
	return err
}

const getOAuth2ClientTokenByAccess = `-- name: GetOAuth2ClientTokenByAccess :one

SELECT
	oauth2_client_tokens.id,
	oauth2_client_tokens.client_id,
	oauth2_client_tokens.belongs_to_user,
	oauth2_client_tokens.redirect_uri,
	oauth2_client_tokens.scope,
	oauth2_client_tokens.code,
	oauth2_client_tokens.code_challenge,
	oauth2_client_tokens.code_challenge_method,
	oauth2_client_tokens.code_created_at,
	oauth2_client_tokens.code_expires_at,
	oauth2_client_tokens.access,
	oauth2_client_tokens.access_created_at,
	oauth2_client_tokens.access_expires_at,
	oauth2_client_tokens.refresh,
	oauth2_client_tokens.refresh_created_at,
	oauth2_client_tokens.refresh_expires_at
FROM oauth2_client_tokens
WHERE oauth2_client_tokens.access = $1
`

func (q *Queries) GetOAuth2ClientTokenByAccess(ctx context.Context, db DBTX, access string) (*Oauth2ClientTokens, error) {
	row := db.QueryRowContext(ctx, getOAuth2ClientTokenByAccess, access)
	var i Oauth2ClientTokens
	err := row.Scan(
		&i.ID,
		&i.ClientID,
		&i.BelongsToUser,
		&i.RedirectUri,
		&i.Scope,
		&i.Code,
		&i.CodeChallenge,
		&i.CodeChallengeMethod,
		&i.CodeCreatedAt,
		&i.CodeExpiresAt,
		&i.Access,
		&i.AccessCreatedAt,
		&i.AccessExpiresAt,
		&i.Refresh,
		&i.RefreshCreatedAt,
		&i.RefreshExpiresAt,
	)
	return &i, err
}

const getOAuth2ClientTokenByCode = `-- name: GetOAuth2ClientTokenByCode :one

SELECT
	oauth2_client_tokens.id,
	oauth2_client_tokens.client_id,
	oauth2_client_tokens.belongs_to_user,
	oauth2_client_tokens.redirect_uri,
	oauth2_client_tokens.scope,
	oauth2_client_tokens.code,
	oauth2_client_tokens.code_challenge,
	oauth2_client_tokens.code_challenge_method,
	oauth2_client_tokens.code_created_at,
	oauth2_client_tokens.code_expires_at,
	oauth2_client_tokens.access,
	oauth2_client_tokens.access_created_at,
	oauth2_client_tokens.access_expires_at,
	oauth2_client_tokens.refresh,
	oauth2_client_tokens.refresh_created_at,
	oauth2_client_tokens.refresh_expires_at
FROM oauth2_client_tokens
WHERE oauth2_client_tokens.code = $1
`

func (q *Queries) GetOAuth2ClientTokenByCode(ctx context.Context, db DBTX, code string) (*Oauth2ClientTokens, error) {
	row := db.QueryRowContext(ctx, getOAuth2ClientTokenByCode, code)
	var i Oauth2ClientTokens
	err := row.Scan(
		&i.ID,
		&i.ClientID,
		&i.BelongsToUser,
		&i.RedirectUri,
		&i.Scope,
		&i.Code,
		&i.CodeChallenge,
		&i.CodeChallengeMethod,
		&i.CodeCreatedAt,
		&i.CodeExpiresAt,
		&i.Access,
		&i.AccessCreatedAt,
		&i.AccessExpiresAt,
		&i.Refresh,
		&i.RefreshCreatedAt,
		&i.RefreshExpiresAt,
	)
	return &i, err
}

const getOAuth2ClientTokenByRefresh = `-- name: GetOAuth2ClientTokenByRefresh :one

SELECT
	oauth2_client_tokens.id,
	oauth2_client_tokens.client_id,
	oauth2_client_tokens.belongs_to_user,
	oauth2_client_tokens.redirect_uri,
	oauth2_client_tokens.scope,
	oauth2_client_tokens.code,
	oauth2_client_tokens.code_challenge,
	oauth2_client_tokens.code_challenge_method,
	oauth2_client_tokens.code_created_at,
	oauth2_client_tokens.code_expires_at,
	oauth2_client_tokens.access,
	oauth2_client_tokens.access_created_at,
	oauth2_client_tokens.access_expires_at,
	oauth2_client_tokens.refresh,
	oauth2_client_tokens.refresh_created_at,
	oauth2_client_tokens.refresh_expires_at
FROM oauth2_client_tokens
WHERE oauth2_client_tokens.refresh = $1
`

func (q *Queries) GetOAuth2ClientTokenByRefresh(ctx context.Context, db DBTX, refresh string) (*Oauth2ClientTokens, error) {
	row := db.QueryRowContext(ctx, getOAuth2ClientTokenByRefresh, refresh)
	var i Oauth2ClientTokens
	err := row.Scan(
		&i.ID,
		&i.ClientID,
		&i.BelongsToUser,
		&i.RedirectUri,
		&i.Scope,
		&i.Code,
		&i.CodeChallenge,
		&i.CodeChallengeMethod,
		&i.CodeCreatedAt,
		&i.CodeExpiresAt,
		&i.Access,
		&i.AccessCreatedAt,
		&i.AccessExpiresAt,
		&i.Refresh,
		&i.RefreshCreatedAt,
		&i.RefreshExpiresAt,
	)
	return &i, err
}
