#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "auth.h"
#include "password.h"

/* ---------------- Schema ---------------- */

int auth_init(sqlite3 *db)
{
    const char *sql =
        "CREATE TABLE IF NOT EXISTS users ("
        "  id         INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username   TEXT    NOT NULL UNIQUE,"
        "  salt       BLOB    NOT NULL,"
        "  hash       BLOB    NOT NULL,"
        "  iterations INTEGER NOT NULL,"
        "  balance    INTEGER NOT NULL DEFAULT 1000 CHECK (balance >= 0),"
        "  created_at TEXT    NOT NULL DEFAULT (datetime('now'))"
        ");";
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "auth_init: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ---------------- Register ---------------- */

int auth_register(sqlite3 *db, const char *username, const char *password)
{
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];

    if (random_bytes(salt, SALT_LEN) != 0) {
        fprintf(stderr, "RNG failure.\n");
        return -1;
    }
    derive_hash(password, salt, SALT_LEN, PBKDF2_ITER, hash);

    const char *sql =
        "INSERT INTO users (username, salt, hash, iterations, balance) "
        "VALUES (?, ?, ?, ?, 1000);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Prepare: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, salt, SALT_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, hash, HASH_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 4, PBKDF2_ITER);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_CONSTRAINT) {
        return -2;   /* duplicate username */
    }
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    return 0;
}

/* ---------------- Login ---------------- */

int auth_login(sqlite3 *db, const char *username, const char *password,
               int *user_id_out)
{
    const char *sql =
        "SELECT id, salt, hash, iterations FROM users WHERE username = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;   /* user not found */
    }

    int id           = sqlite3_column_int (stmt, 0);
    const void *salt = sqlite3_column_blob(stmt, 1);
    int salt_len     = sqlite3_column_bytes(stmt, 1);
    const void *hash = sqlite3_column_blob(stmt, 2);
    int hash_len     = sqlite3_column_bytes(stmt, 2);
    int iters        = sqlite3_column_int (stmt, 3);

    if (salt_len != SALT_LEN || hash_len != HASH_LEN) {
        sqlite3_finalize(stmt);
        return -1;
    }

    uint8_t salt_copy[SALT_LEN];
    uint8_t hash_copy[HASH_LEN];
    memcpy(salt_copy, salt, SALT_LEN);
    memcpy(hash_copy, hash, HASH_LEN);
    sqlite3_finalize(stmt);

    uint8_t computed[HASH_LEN];
    derive_hash(password, salt_copy, SALT_LEN, iters, computed);

    if (!secure_compare(computed, hash_copy, HASH_LEN))
        return -1;

    *user_id_out = id;
    return 0;
}

int auth_get_all_users(sqlite3 *db, AuthUser **users_out, size_t *count_out)
{
    const char *sql =
        "SELECT id, username, balance, created_at "
        "FROM users ORDER BY id;";
    sqlite3_stmt *stmt = NULL;
    AuthUser *users = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (users_out == NULL || count_out == NULL)
        return -1;

    *users_out = NULL;
    *count_out = 0;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 8 : capacity * 2;
            AuthUser *resized = realloc(users,
                                        new_capacity * sizeof(*users));
            if (resized == NULL) {
                sqlite3_finalize(stmt);
                free(users);
                return -1;
            }
            users = resized;
            capacity = new_capacity;
        }

        users[count].id = sqlite3_column_int(stmt, 0);
        snprintf(users[count].username, sizeof(users[count].username), "%s",
                 sqlite3_column_text(stmt, 1));
        users[count].balance = sqlite3_column_int(stmt, 2);
        snprintf(users[count].created_at, sizeof(users[count].created_at), "%s",
                 sqlite3_column_text(stmt, 3));
        count++;
    }

    if (sqlite3_errcode(db) != SQLITE_OK && sqlite3_errcode(db) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        free(users);
        return -1;
    }

    sqlite3_finalize(stmt);
    *users_out = users;
    *count_out = count;
    return 0;
}

/* ---------------- Balance helpers ---------------- */

int auth_get_balance(sqlite3 *db, int user_id)
{
    const char *sql = "SELECT balance FROM users WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(stmt, 1, user_id);

    int bal = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        bal = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return bal;
}

int auth_deduct_bet(sqlite3 *db, int user_id, int bet)
{
    const char *sql =
        "UPDATE users SET balance = balance - ? "
        " WHERE id = ? AND balance >= ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -2;

    sqlite3_bind_int(stmt, 1, bet);
    sqlite3_bind_int(stmt, 2, user_id);
    sqlite3_bind_int(stmt, 3, bet);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -2;
    if (sqlite3_changes(db) == 0) return -1;   /* insufficient funds */
    return 0;
}

int auth_add_winnings(sqlite3 *db, int user_id, int amount)
{
    const char *sql =
        "UPDATE users SET balance = balance + ? WHERE id = ?;";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_int(stmt, 1, amount);
    sqlite3_bind_int(stmt, 2, user_id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}