# Database Tunneling

This guide covers using ToxTunnel to securely access databases (PostgreSQL, MySQL, Redis, MongoDB, etc.) through the Tox P2P network.

## Table of Contents

1. [Single-Machine Testing](#single-machine-testing)
2. [Two-Machine Deployment](#two-machine-deployment)
3. [Supported Database Systems](#supported-database-systems)
4. [Connection Security](#connection-security)
5. [Performance Optimization](#performance-optimization)
6. [Troubleshooting](#troubleshooting)

---

## Single-Machine Testing

Test database tunneling locally before deploying to two separate machines.

### Setup a Test Database

1. **Install PostgreSQL** (for testing):

```bash
# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib

# macOS
brew install postgresql
brew services start postgresql

# Create a test database
sudo -u postgres psql -c "CREATE DATABASE test_db;"
sudo -u postgres psql -c "CREATE USER test_user WITH PASSWORD 'password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE test_db TO test_user;"
```

2. **Set up test data**:

```bash
# Connect to the test database
psql -h localhost -U test_user -d test_db

-- Create a test table
CREATE TABLE test_table (id SERIAL, name VARCHAR(100), created_at TIMESTAMP DEFAULT NOW());

-- Insert test data
INSERT INTO test_table (name) VALUES ('Test Entry 1'), ('Test Entry 2');

-- Verify data
SELECT * FROM test_table;
```

### Start ToxTunnel Server

```bash
# Terminal 1: Start server
./build/toxtunnel -m server -d /tmp/toxtunnel-server
```

Copy the server's Tox address from the output.

> Aliases registered with `toxtunnel servers add <alias> <tox_id>` work
> anywhere a Tox ID is expected — see `docs/CONFIGURATION.md`'s
> "Known-Servers Registry" section.

### Start ToxTunnel Client

```bash
# Terminal 2: Start client
SERVER_ID="PASTE_SERVER_TOX_ADDRESS_HERE"

cat > /tmp/toxtunnel-db-client.yaml <<EOF
mode: client
data_dir: /tmp/toxtunnel-client

client:
  server_id: "${SERVER_ID}"
  forwards:
    - local_port: 5432
      remote_host: 127.0.0.1
      remote_port: 5432
EOF

./build/toxtunnel -c /tmp/toxtunnel-db-client.yaml
```

### Connect to Tunnel

```bash
# Terminal 3: Connect to PostgreSQL through the tunnel
psql -h localhost -p 5432 -U test_user -d test_db

# Execute queries
SELECT * FROM test_table;
\dt
```

### Test with a Python Script

```python
# Install psycopg2 if needed
pip install psycopg2-binary

# test_db.py
import psycopg2

conn = psycopg2.connect(
    host='localhost',
    port=5432,
    user='test_user',
    password='password',
    database='test_db'
)

cur = conn.cursor()
cur.execute('SELECT * FROM test_table;')
rows = cur.fetchall()

for row in rows:
    print(f"ID: {row[0]}, Name: {row[1]}, Created: {row[2]}")

cur.close()
conn.close()
```

Run the test:
```bash
python3 test_db.py
```

---

## Two-Machine Deployment

Access a database server on a remote machine through ToxTunnel.

### Scenario: Remote Database Access

You have a database server running on a remote machine that you need to access securely.

#### Machine A (Remote - Database Server)

The machine hosting the database server.

1. **Ensure your database is running and accessible**

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check port is listening
netstat -tlnp | grep 5432

# If not running on all interfaces, listen on localhost
# Edit /etc/postgresql/*/main/postgresql.conf
# Set: listen_addresses = 'localhost'
sudo systemctl restart postgresql
```

2. **Configure database access (important!)**

For security, allow connections only from localhost:

```bash
# Update pg_hba.conf for PostgreSQL
echo "local   all             all                                   trust" | sudo tee -a /etc/postgresql/*/main/pg_hba.conf
```

3. **Start ToxTunnel Server**

```bash
sudo ./build/toxtunnel -m server -d /var/lib/toxtunnel
```

4. **Copy the Tox address**

Save the 76-character Tox address.

#### Machine B (Local - Your Workstation)

The machine from which you want to access the database.

1. **Create client config file** `db_client.yaml`:

```yaml
mode: client
data_dir: ~/.config/toxtunnel

logging:
  level: info

client:
  # Paste the server's Tox address here
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    - local_port: 5432      # Local port to listen on
      remote_host: 127.0.0.1  # Database server on remote machine
      remote_port: 5432      # PostgreSQL port
```

2. **Start the client**

```bash
./build/toxtunnel -c db_client.yaml
```

Wait for the connection message:
```
Server friend 0 is now online
Listening on local port 5432 -> 127.0.0.1:5432
```

3. **Connect to the remote database**

```bash
psql -h localhost -p 5432 -U your_username -d your_database
```

### Scenario: Multiple Database Services

Forward multiple database services from one remote machine:

```yaml
# Config on local machine
client:
  server_id: "PASTE_SERVER_TOX_ADDRESS_HERE"

  forwards:
    # PostgreSQL
    - local_port: 5432
      remote_host: 127.0.0.1
      remote_port: 5432

    # MySQL
    - local_port: 3306
      remote_host: 127.0.0.1
      remote_port: 3306

    # Redis
    - local_port: 6379
      remote_host: 127.0.0.1
      remote_port: 6379

    # MongoDB
    - local_port: 27017
      remote_host: 127.0.0.1
      remote_port: 27017
```

---

## Supported Database Systems

### PostgreSQL

| Port | Default Config | Notes |
|------|----------------|-------|
| 5432 | localhost:5432 | Ensure `pg_hba.conf` allows connections |

**Connection string**:
```bash
# Direct
psql -h localhost -p 5432 -U user

# With TLS (if enabled)
psql -h localhost -p 5432 -U user --sslmode=require
```

### MySQL/MariaDB

| Port | Default Config | Notes |
|------|----------------|-------|
| 3306 | localhost:3306 | Set `bind-address = 127.0.0.1` in my.cnf |

**Connection string**:
```bash
# Command line
mysql -h localhost -P 3306 -u user -p

# Python (pymysql)
pip install pymysql
python3 -c "
import pymysql
conn = pymysql.connect(
    host='localhost',
    port=3306,
    user='user',
    password='password'
)
..."
```

### Redis

| Port | Default Config | Notes |
|------|----------------|-------|
| 6379 | localhost:6379 | No authentication by default |

**Connection string**:
```bash
# CLI
redis-cli -h localhost -p 6379

# Python (redis)
pip install redis
python3 -c "
import redis
r = redis.Redis(host='localhost', port=6379)
r.set('key', 'value')
print(r.get('key'))
"
```

### MongoDB

| Port | Default Config | Notes |
|------|----------------|-------|
| 27017 | localhost:27017 | Default port |

**Connection string**:
```bash
# CLI
mongosh "mongodb://localhost:27017"

# Python (pymongo)
pip install pymongo
python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://localhost:27017/')
db = client['test']
db.test.insert_one({'message': 'hello from ToxTunnel'})
"
```

### SQLite

SQLite is file-based and does not speak TCP on its own, so it is not a direct fit for ToxTunnel.
Use ToxTunnel to reach an SSH service, a custom application protocol, or a database proxy on the
remote machine instead.

```bash
# Recommended approach: tunnel SSH, then copy or mount the SQLite file securely
ssh -o ProxyCommand="toxtunnel -m client --server-id SERVER_ID --pipe 127.0.0.1:22" user@dummy

# Once connected, work with the database file on the remote host
sqlite3 /path/to/database.db
```

---

## Connection Security

### Database Security Best Practices

1. **Always use database authentication**
   - Create specific users for tunnel access
   - Use strong passwords
   - Restrive privileges with least privilege principle

2. **Enable TLS for database connections**
   - PostgreSQL: SSL mode in connection
   - MySQL: Require SSL
   - MongoDB: TLS enabled

3. **Firewall rules**
   - Only allow localhost access on remote machine
   - Block direct external connections

### Example: Secure PostgreSQL Setup

On remote machine:

```bash
# Create a dedicated user for tunnel access
sudo -u postgres createuser --interactive --pwprompt
# Name: toxtunnel_user
# Password: secure_password
# Role: superuser (for testing) or specific privileges

# Ensure only localhost connections
echo "listen_addresses = 'localhost'" | sudo tee /etc/postgresql/*/main/postgresql.conf
```

Connect from local machine:

```bash
psql -h localhost -p 5432 -U toxtunnel_user -d your_database \
    --sslmode=require
```

### Connection Pooling

For better performance with many connections:

```python
# Python example using connection pooling
import psycopg2.pool

pool = psycopg2.pool.SimpleConnectionPool(
    1, 5,  # min, max connections
    host='localhost',
    port=5432,
    user='user',
    password='password',
    database='db'
)

conn = pool.getconn()
# Use connection
pool.putconn(conn)
```

---

## Performance Optimization

### Batch Operations

Minimize round trips by batching operations:

```python
# Bad - One query per row
for row in data:
    cursor.execute("INSERT INTO table VALUES (%s)", (row,))

# Good - Batch insert
cursor.executemany("INSERT INTO table VALUES (%s)", data)
```

### Compression

For large datasets:

```python
# Python with zlib
import zlib
import psycopg2

def send_compressed_data(conn, data):
    compressed = zlib.compress(str(data).encode())
    with conn.cursor() as cur:
        cur.execute("INSERT INTO large_data (compressed_data) VALUES (%s)",
                    (compressed,))
```

### Connection Reuse

Keep connections open to avoid tunnel handshake overhead:

```bash
# Use a connection pooler
pgbouncer -d postgres://user:pass@localhost:5432/db
```

### Performance Testing

Test tunnel performance:

```python
import time
import psycopg2

conn = psycopg2.connect(
    host='localhost',
    port=5432,
    user='user',
    password='password',
    database='test'
)

# Test insert performance
start = time.time()
with conn.cursor() as cur:
    cur.execute("INSERT INTO test_table (name) VALUES ('bulk_insert')")
conn.commit()
end = time.time()
print(f"Insert time: {end - start:.3f}s")

# Test query performance
start = time.time()
with conn.cursor() as cur:
    cur.execute("SELECT * FROM test_table")
    rows = cur.fetchall()
end = time.time()
print(f"Query time: {end - start:.3f}s")
```

---

## Troubleshooting

### Connection Refused

**Symptom**: `psql: FATAL: connection to server failed`

**Check**:
1. ToxTunnel client is running
2. Tox connection established (look for "Server friend X is now online")
3. Database server is running on remote machine
4. Database listens on localhost (not just localhost)
5. No firewall blocking access

**Debug**:
```bash
# Check remote database
ssh remote-server "netstat -tlnp | grep 5432"

# Check local tunnel
lsof -i :5432

# Enable debug logging
./build/toxtunnel -m client --server-id ID -d /tmp -v debug
```

### Authentication Failed

**Symptom**: `psql: FATAL: password authentication failed`

**Solutions**:
1. Verify username and password
2. Check user has permission to connect to the database
3. Ensure password is being sent correctly

### Performance Issues

**Symptom**: Slow queries or connections

**Solutions**:
1. Test direct connection vs tunnel
2. Check network latency between machines
3. Enable database query logging
4. Use connection pooling

### Tunnel Specific Errors

**Symptom**: No errors, but no data through

**Debug flow**:
```bash
1. Monitor ToxTunnel logs on both machines
2. Check tunnel is connected (tunnel list command if available)
3. Verify target service is accessible locally on remote machine
4. Test with simpler tools (telnet/nc)
```

---

## Integration with Development Tools

### DBeaver/Postico

Configure database connection:

| Field | Value |
|-------|-------|
| Host | localhost |
| Port | Local tunnel port (e.g., 5432) |
| Database | Remote database name |
| Username | Database username |
| Password | Database password |

### ORM Integration

#### SQLAlchemy (Python)
```python
import sqlalchemy
engine = sqlalchemy.create_engine(
    'postgresql://user:password@localhost:5432/db_name'
)
```

#### Django
```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'db_name',
        'USER': 'user',
        'PASSWORD': 'password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

#### Node.js (Knex)
```javascript
const knex = require('knex')({
  client: 'pg',
  connection: {
    host: 'localhost',
    port: 5432,
    user: 'user',
    password: 'password',
    database: 'db_name'
  }
});
```

---

## Example: Complete Database Access Workflow

### Remote Server Setup

```bash
# 1. Install database
sudo apt install postgresql

# 2. Create tunnel user
sudo -u postgres psql -c "CREATE USER app_user WITH PASSWORD 'secret123';"

# 3. Create app database
sudo -u postgres psql -c "CREATE DATABASE app_db WITH OWNER app_user;"

# 4. Start ToxTunnel
sudo ./build/toxtunnel -m server
```

### Local Setup

```bash
# 1. Start client
./build/toxtunnel -c client.yaml -d ~/.config/toxtunnel

# 2. Connect to database
psql -h localhost -p 5432 -U app_user -d app_db

# 3. Run your application (configured for localhost:5432)
python manage.py runserver
```

### Best Practices Checklist

- [ ] Test connectivity with simple tools first
- [ ] Use dedicated user accounts for tunnel access
- [ ] Encrypt sensitive data at rest and in transit
- [ ] Monitor connection performance
- [ ] Have backup authentication methods
- [ ] Regularly update database software
- [ ] Implement proper error handling
