"""
    Module to define MFA registry queries
"""

INSERT_MFA_KEY_QUERY: str = """
INSERT INTO
    mfa_keys (created_at, updated_at, mfa_key, user_uuid)
VALUES
    (%(created_at)s, %(updated_at)s, %(mfa_key)s, %(user_uuid)s)
"""
