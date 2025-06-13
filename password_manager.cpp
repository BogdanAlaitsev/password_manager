#include "password_manager.h"
#include <sqlite3.h>
#include <iostream>
#include <CommonCrypto/CommonCrypto.h>
#include <sstream>
#include <iomanip>

std::string PasswordManager::sha256(const std::string& input) {
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(input.data(), static_cast<CC_LONG>(input.size()), hash);

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) {
        out << std::setw(2) << static_cast<int>(hash[i]);
    }
    return out.str();
}

PasswordManager::PasswordManager(const std::string& dbFile) : db(nullptr) {
    if (sqlite3_open(dbFile.c_str(), reinterpret_cast<sqlite3**>(&db)) != SQLITE_OK) {
        std::cerr << "Can't open database: "
                  << sqlite3_errmsg(reinterpret_cast<sqlite3*>(db))
                  << std::endl;
        db = nullptr;
    } else if (!initDB()) {
        std::cerr << "Failed to initialize DB" << std::endl;
    }
}

PasswordManager::~PasswordManager() {
    if (db) {
        sqlite3_close(reinterpret_cast<sqlite3*>(db));
        db = nullptr;
    }
}

bool PasswordManager::initDB() {
    if (!db) return false;

    const char* userTableSql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    )";
    const char* passwordTableSql = R"(
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            login TEXT NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    char* errMsg = nullptr;
    if (sqlite3_exec(reinterpret_cast<sqlite3*>(db), userTableSql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error (users): " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    if (sqlite3_exec(reinterpret_cast<sqlite3*>(db), passwordTableSql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error (passwords): " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool PasswordManager::addUser(const std::string& username,
                              const std::string& password) {
    if (!db) return false;

    const char* sql = "INSERT INTO users (username, password) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    std::string hashed = sha256(password);

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(),   -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    bool ok = (sqlite3_changes(reinterpret_cast<sqlite3*>(db)) > 0);
    sqlite3_finalize(stmt);
    return ok;
}

int PasswordManager::authenticate(const std::string& username,
                                  const std::string& password) {
    if (!db) return -1;

    const char* sql = "SELECT id, password FROM users WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    int userId = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id         = sqlite3_column_int(stmt, 0);
        const char* dbHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        // Compare stored hash with hash of provided password
        if (sha256(password) == dbHash) {
            userId = id;
        }
    }
    sqlite3_finalize(stmt);
    return userId;
}

std::vector<User> PasswordManager::getAllUsers() {
    std::vector<User> users;
    if (!db) return users;

    const char* sql = "SELECT id, username, password FROM users;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr) != SQLITE_OK)
        return users;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        User u;
        u.id       = sqlite3_column_int(stmt, 0);
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        u.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        users.push_back(u);
    }
    sqlite3_finalize(stmt);
    return users;
}

bool PasswordManager::deleteUser(int userId) {
    if (!db) return false;

    {
        const char* sql = "DELETE FROM passwords WHERE user_id = ?;";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    {
        const char* sql = "DELETE FROM users WHERE id = ?;";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
        sqlite3_bind_int(stmt, 1, userId);
        sqlite3_step(stmt);
        bool ok = (sqlite3_changes(reinterpret_cast<sqlite3*>(db)) > 0);
        sqlite3_finalize(stmt);
        return ok;
    }
}

bool PasswordManager::addPassword(int userId,
                                  const std::string& title,
                                  const std::string& url,
                                  const std::string& login,
                                  const std::string& password) {
    if (!db) return false;

    const char* sql =
        "INSERT INTO passwords (user_id, title, url, login, password) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt,    1, userId);
    sqlite3_bind_text(stmt,   2, title.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,   3, url.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,   4, login.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt,   5, password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    bool ok = (sqlite3_changes(reinterpret_cast<sqlite3*>(db)) > 0);
    sqlite3_finalize(stmt);
    return ok;
}

std::vector<PasswordEntry> PasswordManager::getPasswordsForUser(int userId) {
    std::vector<PasswordEntry> passwords;
    if (!db) return passwords;

    const char* sql =
        "SELECT id, user_id, title, url, login, password FROM passwords WHERE user_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, userId);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PasswordEntry p;
        p.id       = sqlite3_column_int(stmt, 0);
        p.userId   = sqlite3_column_int(stmt, 1);
        p.title    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        p.url      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        p.login    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        p.password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        passwords.push_back(p);
    }
    sqlite3_finalize(stmt);
    return passwords;
}

bool PasswordManager::updatePassword(int passwordId,
                                     const std::string& title,
                                     const std::string& url,
                                     const std::string& login,
                                     const std::string& password) {
    if (!db) return false;

    const char* sql =
        "UPDATE passwords SET title = ?, url = ?, login = ?, password = ? WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, title.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, url.c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, login.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, passwordId);
    sqlite3_step(stmt);
    bool ok = (sqlite3_changes(reinterpret_cast<sqlite3*>(db)) > 0);
    sqlite3_finalize(stmt);
    return ok;
}

bool PasswordManager::deletePassword(int passwordId) {
    if (!db) return false;

    const char* sql = "DELETE FROM passwords WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(reinterpret_cast<sqlite3*>(db), sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, passwordId);
    sqlite3_step(stmt);
    bool ok = (sqlite3_changes(reinterpret_cast<sqlite3*>(db)) > 0);
    sqlite3_finalize(stmt);
    return ok;
}
