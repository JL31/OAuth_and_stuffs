------------------------------------
--- SQL scripts to create tables ---
------------------------------------

-- Note : the "uuid-ossp" extension installation is mandatory to use the UUID column type

CREATE TABLE IF NOT EXISTS token_cryptographic_data (
    uuid UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    encryption_key BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    encrypted_token BYTEA NOT NULL,
    tag BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS token_data (
    uuid UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    token_cryptographic_data UUID REFERENCES token_cryptographic_data (uuid),
    token_type VARCHAR(100) NOT NULL,
    token_scope TEXT[],
    oauth_provider VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS users_passwords (
    uuid UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    uuid UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    user_password UUID REFERENCES users_passwords (uuid)
);
