package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	_ "github.com/lib/pq"
	postgresqlv1alpha1 "github.com/rgeraskin/psql-roles-operator/api/v1alpha1"
	"go.uber.org/zap/zapcore"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type Client struct {
	logger           logr.Logger
	connectionString string
	db               *sql.DB
}

func NewClient(ctx context.Context, connectionString string) (*Client, error) {
	// logger := log.FromContext(ctx).WithName("postgres")
	opts := zap.Options{}
	opts.Development = true
	opts.Level = zapcore.Level(-2)
	opts.EncoderConfigOptions = []zap.EncoderConfigOption{
		func(config *zapcore.EncoderConfig) {
			config.EncodeLevel = zapcore.CapitalColorLevelEncoder
		},
	}
	logger := zap.New(zap.UseFlagOptions(&opts)).WithName("postgres")

	logger.V(2).Info("connecting to database", "connectionString", connectionString)
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	client := &Client{
		logger:           logger,
		connectionString: connectionString,
		db:               db,
	}

	return client, nil
}

func (c *Client) Close() error {
	return c.db.Close()
}

// CreateRole creates a new PostgreSQL role
func (c *Client) CreateRole(role *postgresqlv1alpha1.Role) error {
	query := fmt.Sprintf(`CREATE ROLE %s`, role.Name)
	if role.Login {
		query += " LOGIN"
	}
	if role.Replication {
		query += " REPLICATION"
	}

	c.logger.V(2).Info("CreateRole: query", "query", query)

	_, err := c.db.Exec(query)
	return err
}

func (c *Client) SetRoleDescription(name string, description string) error {
	var comment string
	if description == "" {
		comment = "NULL"
	} else {
		comment = fmt.Sprintf("'%s'", description)
	}

	query := fmt.Sprintf(`COMMENT ON ROLE %s IS %s`, name, comment)
	c.logger.V(2).Info("SetRoleDescription: query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

func (c *Client) SetRoleLogin(name string, login bool) error {
	var alter string
	if login {
		alter = "LOGIN"
	} else {
		alter = "NOLOGIN"
	}
	query := fmt.Sprintf(`ALTER ROLE %s %s`, name, alter)
	c.logger.V(2).Info("SetRoleLogin: query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

func (c *Client) SetRoleReplication(name string, replication bool) error {
	var alter string
	if replication {
		alter = "REPLICATION"
	} else {
		alter = "NOREPLICATION"
	}
	query := fmt.Sprintf(`ALTER ROLE %s %s`, name, alter)
	c.logger.V(2).Info("SetRoleReplication: query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

func (c *Client) SetRoleMemberOf(name string, memberOf []string) error {
	// current memberOf
	query := fmt.Sprintf(`
		SELECT r.rolname AS member_of
		FROM pg_roles r
		JOIN pg_auth_members am ON r.oid = am.roleid
		JOIN pg_roles m ON m.oid = am.member
		WHERE m.rolname = '%s';
		`,
		name,
	)
	// replace all whitespaces and newlines with single space
	query = strings.Join(strings.Fields(query), " ")

	c.logger.V(2).Info("SetRoleMemberOf: query current memberOf", "query", query)
	rows, err := c.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query memberOf: %w", err)
	}
	defer rows.Close()

	c.logger.V(2).Info("SetRoleMemberOf: read current memberOf")
	var currentMemberOf []string
	for rows.Next() {
		var memberOf string
		if err := rows.Scan(&memberOf); err != nil {
			return fmt.Errorf("failed to scan memberOf: %w", err)
		}
		currentMemberOf = append(currentMemberOf, memberOf)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating memberOf: %w", err)
	}

	c.logger.V(2).Info("SetRoleMemberOf: current memberOf", "memberOf", currentMemberOf)

	// remove extra memberOf
	for _, member := range currentMemberOf {
		if !slices.Contains(memberOf, member) {
			query := fmt.Sprintf(`REVOKE %s FROM %s`, member, name)
			c.logger.V(2).
				Info(
					"SetRoleMemberOf: remove member '%s' from role '%s'",
					"roleName", name,
					"role", member,
					"query", query,
				)
			_, err := c.db.Exec(query)
			if err != nil {
				return fmt.Errorf("failed to revoke member: %w", err)
			}
		}
	}
	// add new memberOf
	for _, member := range memberOf {
		if !slices.Contains(currentMemberOf, member) {
			query := fmt.Sprintf(`GRANT %s TO %s`, member, name)
			c.logger.V(2).
				Info(
					"SetRoleMemberOf: add new member '%s' to role '%s'",
					"roleName", name,
					"role", member,
					"query", query,
				)
			_, err := c.db.Exec(query)
			if err != nil {
				return fmt.Errorf("failed to grant member: %w", err)
			}
		}
	}

	return nil
}

func (c *Client) SetRoleUsers(name string, users []string) error {
	// current users
	query := fmt.Sprintf(`
		SELECT r.rolname
		FROM pg_roles r
		JOIN pg_auth_members m ON r.oid = m.member
		JOIN pg_roles gr ON gr.oid = m.roleid
		WHERE gr.rolname = '%s'
		AND r.rolcanlogin = true;
		`,
		name,
	)
	// replace all whitespaces and newlines with single space
	query = strings.Join(strings.Fields(query), " ")

	c.logger.V(2).Info("SetRoleUsers: query current users", "query", query)
	rows, err := c.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	c.logger.V(2).Info("SetRoleUsers: read current users")
	var currentUsers []string
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return fmt.Errorf("failed to scan user: %w", err)
		}
		currentUsers = append(currentUsers, user)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating users: %w", err)
	}

	c.logger.V(2).Info("SetRoleUsers: current users", "users", currentUsers)

	// drop extra users
	for _, user := range currentUsers {
		if !slices.Contains(users, user) {
			err := c.DropRole(user)
			if err != nil {
				return fmt.Errorf("failed to drop user: %w", err)
			}
		}
	}

	// add new users
	for _, user := range users {
		if !slices.Contains(currentUsers, user) {
			err := c.CreateRole(&postgresqlv1alpha1.Role{
				Name:  user,
				Login: true,
			})
			if err != nil {
				return fmt.Errorf("failed to create user: %w", err)
			}
		}
	}

	return nil
}

// DropRole drops a PostgreSQL role
func (c *Client) DropRole(name string) error {
	c.logger.V(2).Info("DropRole", "name", name)
	query := fmt.Sprintf(`DROP ROLE IF EXISTS %s`, name)
	c.logger.V(2).Info("DropRole query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

func (c *Client) setRoleGrantsTables(name string, grants []postgresqlv1alpha1.Grant) error {
	// current grants for tables
	// is_grantable is ignored for now
	query := fmt.Sprintf(`
		SELECT
			table_schema,
			table_name,
			privilege_type
		FROM
			information_schema.role_table_grants
		WHERE
			table_schema NOT IN ('pg_catalog', 'information_schema') AND grantee = '%s'
		ORDER BY
			table_schema, table_name;
		`,
		name,
	)
	// replace all whitespaces and newlines with single space
	query = strings.Join(strings.Fields(query), " ")

	c.logger.V(2).Info("setRoleGrantsTables: query current grants for tables", "query", query)
	rows, err := c.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query grants: %w", err)
	}
	defer rows.Close()

	c.logger.V(2).Info("setRoleGrantsTables: read current grants for tables")
	type Grant struct {
		Schema    string
		Object    string
		Privilege string
		// WithGrantOption bool
	}

	var currentGrants []Grant
	for rows.Next() {
		var grant Grant
		if err := rows.Scan(
			&grant.Schema,
			&grant.Object,
			&grant.Privilege,
			// &grant.WithGrantOption,
		); err != nil {
			return fmt.Errorf("failed to scan grant: %w", err)
		}
		currentGrants = append(currentGrants, grant)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating grants: %w", err)
	}

	c.logger.V(2).Info("setRoleGrantsTables: current grants for tables", "grants", currentGrants)

	// expected grants for tables
	var expectedGrants []Grant
	for _, grant := range grants {
		// filter tables only
		if strings.ToLower(grant.ObjectType) != "table" {
			continue
		}

		for _, object := range grant.Objects {
			for _, privilege := range grant.Privileges {
				expectedGrants = append(expectedGrants, Grant{
					Schema:    grant.Schema,
					Object:    object,
					Privilege: strings.ToUpper(privilege),
					// WithGrantOption: grant.WithGrantOption,
				})
			}
		}
	}

	c.logger.V(2).Info("setRoleGrantsTables: expected grants for tables", "grants", expectedGrants)

	// drop extra grants
	for _, grant := range currentGrants {
		if !slices.Contains(expectedGrants, grant) {
			query := fmt.Sprintf(`REVOKE %s ON TABLE %s.%s FROM %s;`,
				grant.Privilege,
				grant.Schema,
				grant.Object,
				name,
			)
			c.logger.V(2).Info("setRoleGrantsTables: revoke extra grant", "query", query)
			_, err := c.db.Exec(query)
			if err != nil {
				return fmt.Errorf("failed to revoke grant: %w", err)
			}
		}
	}

	// add new grants
	for _, grant := range expectedGrants {
		if !slices.Contains(currentGrants, grant) {
			query := fmt.Sprintf(`GRANT %s ON TABLE %s.%s TO %s;`,
				grant.Privilege,
				grant.Schema,
				grant.Object,
				name,
			)
			c.logger.V(2).Info("setRoleGrantsTables: add new grant", "query", query)
			_, err := c.db.Exec(query)
			if err != nil {
				return fmt.Errorf("failed to add grant: %w", err)
			}
		}
	}

	return nil
}

func (c *Client) SetRoleGrants(name string, grants []postgresqlv1alpha1.Grant) error {
	// tables
	err := c.setRoleGrantsTables(name, grants)
	if err != nil {
		return fmt.Errorf("failed to set role grants for tables: %w", err)
	}

	return nil
}

// GrantPrivileges grants privileges to a role
func (c *Client) GrantPrivileges(
	role string,
	privileges []string,
	objectType, database, schema, table string,
	columns []string,
	withGrantOption bool,
) error {
	c.logger.V(2).
		Info("GrantPrivileges", "role", role, "privileges", privileges, "objectType", objectType, "database", database, "schema", schema, "table", table, "columns", columns, "withGrantOption", withGrantOption)
	// Build the GRANT statement
	query := fmt.Sprintf("GRANT %s ON %s", joinPrivileges(privileges), objectType)

	if database != "" {
		query += fmt.Sprintf(" DATABASE %s", database)
	}
	if schema != "" {
		query += fmt.Sprintf(" SCHEMA %s", schema)
	}
	if table != "" {
		query += fmt.Sprintf(" TABLE %s", table)
	}
	if len(columns) > 0 {
		query += fmt.Sprintf(" (%s)", joinColumns(columns))
	}

	query += fmt.Sprintf(" TO %s", role)
	if withGrantOption {
		query += " WITH GRANT OPTION"
	}

	c.logger.V(2).Info("GrantPrivileges query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

// RevokePrivileges revokes privileges from a role
func (c *Client) RevokePrivileges(
	role string,
	privileges []string,
	objectType, database, schema, table string,
	columns []string,
) error {
	c.logger.V(2).
		Info("RevokePrivileges", "role", role, "privileges", privileges, "objectType", objectType, "database", database, "schema", schema, "table", table, "columns", columns)
	// Build the REVOKE statement
	query := fmt.Sprintf("REVOKE %s ON %s", joinPrivileges(privileges), objectType)

	if database != "" {
		query += fmt.Sprintf(" DATABASE %s", database)
	}
	if schema != "" {
		query += fmt.Sprintf(" SCHEMA %s", schema)
	}
	if table != "" {
		query += fmt.Sprintf(" TABLE %s", table)
	}
	if len(columns) > 0 {
		query += fmt.Sprintf(" (%s)", joinColumns(columns))
	}

	query += fmt.Sprintf(" FROM %s", role)

	c.logger.V(2).Info("RevokePrivileges query", "query", query)
	_, err := c.db.Exec(query)
	return err
}

// Helper functions
func joinPrivileges(privileges []string) string {
	if len(privileges) == 0 {
		return "ALL"
	}
	return fmt.Sprintf("%s", privileges)
}

func joinColumns(columns []string) string {
	return fmt.Sprintf("%s", columns)
}
