#ifndef AUTH_H
#define AUTH_H

#include "sqlite3.h"

typedef struct
{
    int id;
    char username[64];
    int balance;
    char created_at[32];
} AuthUser;

/*
 * Create the `users` table if it doesn't exist.
 * Call this once at startup, right after opening the DB.
 * Returns 0 on success, -1 on failure.
 */
int auth_init(sqlite3 *db);

/*
 * Register a new user.
 * Returns:
 *    0  → success
 *   -1  → internal error (RNG, prepare, step)
 *   -2  → username already exists
 */
int auth_register(sqlite3 *db, const char *username, const char *password);

/*
 * Verify credentials.
 * On success, writes the user's id into *user_id_out and returns 0.
 * On failure (no such user, or wrong password) returns -1.
 */
int auth_login(sqlite3 *db, const char *username, const char *password,
               int *user_id_out);

/*
 * Load all users into a newly allocated array.
 * The caller owns the array and must free it.
 * Returns 0 on success, -1 on query or allocation failure.
 */
int auth_get_all_users(sqlite3 *db, AuthUser **users_out, size_t *count_out);

/*
 * Fetch the current balance for a user.
 * Returns the balance, or -1 on error.
 */
int auth_get_balance(sqlite3 *db, int user_id);

/*
 * Deduct `bet` from the user's balance, but only if they have enough.
 * Returns:
 *    0  → success
 *   -1  → insufficient funds or user not found
 *   -2  → internal error
 */
int auth_deduct_bet(sqlite3 *db, int user_id, int bet);

/*
 * Add `amount` to the user's balance (e.g., winnings).
 * Returns 0 on success, -1 on failure.
 */
int auth_add_winnings(sqlite3 *db, int user_id, int amount);

#endif