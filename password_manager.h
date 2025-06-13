/// @file password_manager.h
/// @brief Заголовочный файл, содержащий объявление класса PasswordManager,
///        структур User и PasswordEntry и их Doxygen-комментарии.

#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <string>
#include <vector>

/// @brief Структура пользователя.
/// @details Хранит идентификатор, имя и хеш пароля.
struct User {
    /// @brief Уникальный идентификатор пользователя.
    int id;
    /// @brief Логин пользователя.
    std::string username;
    /// @brief SHA-256 хеш пароля в шестнадцатеричной форме.
    std::string password;
};

/// @brief Запись сервиса для конкретного пользователя.
/// @details Содержит все поля, соответствующие колонкам таблицы passwords.
struct PasswordEntry {
    /// @brief Уникальный идентификатор записи.
    int id;
    /// @brief Идентификатор пользователя-владельца.
    int userId;
    /// @brief Название сервиса.
    std::string title;
    /// @brief URL сервиса.
    std::string url;
    /// @brief Логин на сервисе.
    std::string login;
    /// @brief Пароль на сервисе (открытый текст).
    std::string password;
};

/// @brief Менеджер работы с базой данных пользователей и паролей.
/// @details Открывает/закрывает SQLite, предоставляет CRUD-операции.
class PasswordManager {
private:
    void* db;  ///< @brief Указатель на sqlite3*

    /// @brief Инициализировать таблицы users и passwords.
    /// @return true, если таблицы созданы (или уже существуют).
    bool initDB();

    /// @brief Вычисляет SHA-256 хеш входной строки.
    /// @param input Строка для хеширования.
    /// @return Хеш в виде hex-строки длиной 64 символа.
    std::string sha256(const std::string& input);

public:
    /// @brief Конструктор: открывает базу и инициализирует схему.
    /// @param dbFile Путь к файлу базы SQLite.
    PasswordManager(const std::string& dbFile);

    /// @brief Деструктор: закрывает соединение с базой.
    ~PasswordManager();

    /// @brief Добавляет нового пользователя с хешем пароля.
    /// @param username Логин (уникален).
    /// @param password Пароль в открытом виде.
    /// @return true при успехе, false при ошибке.
    bool addUser(const std::string& username, const std::string& password);

    /// @brief Аутентифицирует пользователя.
    /// @param username Логин.
    /// @param password Пароль в открытом виде.
    /// @return ID пользователя или -1 при неверных данных.
    int authenticate(const std::string& username, const std::string& password);

    /// @brief Получить всех пользователей.
    /// @return Вектор структур User.
    std::vector<User> getAllUsers();

    /// @brief Удалить пользователя и все его пароли.
    /// @param userId Идентификатор пользователя.
    /// @return true, если удалено хотя бы 1 строка.
    bool deleteUser(int userId);

    /// @brief Добавить запись пароля для пользователя.
    /// @param userId ID пользователя.
    /// @param title Название сервиса.
    /// @param url URL сервиса.
    /// @param login Логин на сервисе.
    /// @param password Пароль на сервисе.
    /// @return true при успехе, false при ошибке.
    bool addPassword(int userId,
                     const std::string& title,
                     const std::string& url,
                     const std::string& login,
                     const std::string& password);

    /// @brief Получить все пароли конкретного пользователя.
    /// @param userId ID пользователя.
    /// @return Вектор PasswordEntry.
    std::vector<PasswordEntry> getPasswordsForUser(int userId);

    /// @brief Обновить запись пароля.
    /// @param passwordId ID записи.
    /// @param title Новое название сервиса.
    /// @param url Новый URL.
    /// @param login Новый логин.
    /// @param password Новый пароль.
    /// @return true, если обновлено хотя бы 1 строка.
    bool updatePassword(int passwordId,
                        const std::string& title,
                        const std::string& url,
                        const std::string& login,
                        const std::string& password);

    /// @brief Удалить запись пароля.
    /// @param passwordId ID записи.
    /// @return true, если удалено хотя бы 1 строка.
    bool deletePassword(int passwordId);
};

#endif // PASSWORD_MANAGER_H
