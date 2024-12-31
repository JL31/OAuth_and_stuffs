"""
    Module to define login registry queries
"""

INSERT_CRYPTO_DATA_QUERY: str = """
INSERT INTO
    token_cryptographic_data (created_at, updated_at, encryption_key, iv, encrypted_token, tag)
VALUES
    (%(created_at)s, %(updated_at)s, %(encryption_key)s, %(iv)s, %(encrypted_token)s, %(tag)s)
RETURNING
    token_cryptographic_data.uuid
"""

INSERT_TOKEN_DATA_QUERY: str = """
INSERT INTO
    token_data (created_at, updated_at, token_cryptographic_data, token_type, token_scope, oauth_provider)
VALUES
    (%(created_at)s, %(updated_at)s, %(token_cryptographic_data)s, %(token_type)s, %(token_scope)s, %(oauth_provider)s)
RETURNING
    token_data.uuid
"""

GET_OAUTH_TOKEN_QUERY: str = """
SELECT
    token_cryptographic_data.uuid AS "token_cryptographic_data_uuid",
    token_cryptographic_data.encryption_key,
    token_cryptographic_data.iv,
    token_cryptographic_data.encrypted_token,
    token_cryptographic_data.tag,

    token_data.uuid AS "token_data_uuid",
    token_data.token_type,
    token_data.token_scope,
    token_data.oauth_provider
FROM
    token_cryptographic_data
INNER JOIN
    token_data ON token_data.token_cryptographic_data = token_cryptographic_data.uuid
WHERE
    token_data.uuid = %(token_data_uuid)s
"""

GET_USER_FROM_UUID_QUERY: str = """
SELECT
    uuid
FROM
    users
WHERE
    uuid = %(user_uuid)s
"""

INSERT_PASSWORD_DATA_QUERY: str = """
INSERT INTO
    users_passwords (created_at, updated_at, hashed_password)
VALUES
    (%(created_at)s, %(updated_at)s, %(hashed_password)s)
RETURNING
    users_passwords.uuid
"""

INSERT_USER_DATA_QUERY: str = """
INSERT INTO
    users (created_at, updated_at, email, user_password)
VALUES
    (%(created_at)s, %(updated_at)s, %(email)s, %(user_password_uuid)s)
RETURNING
    users.uuid,
    users.email
"""

GET_USER_FROM_CREDENTIALS_QUERY: str = """
SELECT
    users.uuid
FROM
    users
INNER JOIN
    users_passwords ON users_passwords.uuid = users.user_password
WHERE
    users.email = %(email)s
AND
    users_passwords.hashed_password = %(hashed_password)s
"""
