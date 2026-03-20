from core.database import execute, fetch_all, fetch_one


def get_user_by_username(username: str) -> dict | None:
    sql = """
        SELECT id, username, password_hash, role, created_at
        FROM users
        WHERE username = %s
        LIMIT 1
    """
    return fetch_one(sql, (username,))


def get_user_by_id(user_id: str) -> dict | None:
    sql = """
        SELECT id, username, password_hash, role, created_at
        FROM users
        WHERE id = %s
        LIMIT 1
    """
    return fetch_one(sql, (user_id,))


def list_users() -> list[dict]:
    sql = """
        SELECT id, username, role, created_at
        FROM users
        ORDER BY created_at DESC
    """
    return fetch_all(sql)


def create_user(user_id: str, username: str, password_hash: str, role: str = "user") -> None:
    sql = """
        INSERT INTO users (id, username, password_hash, role)
        VALUES (%s, %s, %s, %s)
    """
    execute(sql, (user_id, username, password_hash, role))


def update_password(user_id: str, password_hash: str) -> None:
    sql = "UPDATE users SET password_hash = %s WHERE id = %s"
    execute(sql, (password_hash, user_id))


def delete_user(user_id: str) -> int:
    sql = "DELETE FROM users WHERE id = %s"
    rows, _ = execute(sql, (user_id,))
    return rows


def count_admin_users() -> int:
    sql = "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'"
    row = fetch_one(sql)
    return int(row["total"]) if row else 0
