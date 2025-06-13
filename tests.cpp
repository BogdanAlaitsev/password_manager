#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "password_manager.h"
#include <filesystem>

static bool looksLikeSha256Hex(const std::string &s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9')
               || (c >= 'a' && c <= 'f')
               || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

TEST_CASE("User management") {
    const std::string testDB = "test_users.db";
    std::filesystem::remove(testDB);
    PasswordManager manager(testDB);

    CHECK(manager.addUser("user1", "pass1") == true);
    CHECK(manager.addUser("user1", "pass2") == false); // Duplicate user
    int userId = manager.authenticate("user1", "pass1");
    CHECK(userId != -1);
    CHECK(manager.authenticate("user1", "wrong") == -1);

    auto users = manager.getAllUsers();
    REQUIRE(users.size() == 1);

    const std::string &storedHash = users[0].password;
    CHECK(storedHash != "pass1");
    CHECK(looksLikeSha256Hex(storedHash));

    CHECK(manager.deleteUser(userId) == true);
    CHECK(manager.authenticate("user1", "pass1") == -1);
    CHECK(manager.getAllUsers().empty());
}

TEST_CASE("Password management") {
    const std::string testDB = "test_passwords.db";
    std::filesystem::remove(testDB);
    PasswordManager manager(testDB);

    REQUIRE(manager.addUser("user1", "pass1") == true);
    int userId = manager.authenticate("user1", "pass1");
    REQUIRE(userId != -1);

    CHECK(manager.addPassword(userId, "Title1", "http://url1", "login1", "pass1") == true);
    CHECK(manager.addPassword(userId, "Title2", "http://url2", "login2", "pass2") == true);

    auto passwords = manager.getPasswordsForUser(userId);
    REQUIRE(passwords.size() == 2);

    int pwdId = passwords[0].id;
    CHECK(manager.updatePassword(pwdId, "NewTitle", "http://newurl", "newlogin", "newpass") == true);

    auto updatedPasswords = manager.getPasswordsForUser(userId);
    auto& updated = updatedPasswords[0];
    CHECK(updated.title == "NewTitle");
    CHECK(updated.url == "http://newurl");
    CHECK(updated.login == "newlogin");
    CHECK(updated.password == "newpass");

    CHECK(manager.deletePassword(pwdId) == true);
    auto afterDelete = manager.getPasswordsForUser(userId);
    CHECK(afterDelete.size() == 1);

    CHECK(manager.deleteUser(userId) == true);
    CHECK(manager.getPasswordsForUser(userId).empty());
}