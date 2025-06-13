#include <iostream>
#include "password_manager.h"

void showMainMenu() {
    std::cout << "Меню:\n";
    std::cout << "1. Добавить пользователя\n";
    std::cout << "2. Авторизация\n";
    std::cout << "3. Просмотр списка всех пользователей\n";
    std::cout << "4. Удалить пользователя\n";
    std::cout << "5. Выход\n";
    std::cout << "Выберите пункт: ";
}

void showPasswordMenu() {
    std::cout << "\nПароли:\n";
    std::cout << "1. Добавить пароль\n";
    std::cout << "2. Просмотр паролей\n";
    std::cout << "3. Редактировать пароль\n";
    std::cout << "4. Удалить пароль\n";
    std::cout << "5. Выход\n";
    std::cout << "Выберите пункт: ";
}

int main() {
    PasswordManager manager("users_passwords.db");

    bool running = true;
    while (running) {
        showMainMenu();
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
            case 1: {
                std::string username, password;
                std::cout << "Введите имя пользователя: ";
                std::getline(std::cin, username);
                std::cout << "Введите пароль: ";
                std::getline(std::cin, password);

                if (manager.addUser(username, password))
                    std::cout << "Пользователь добавлен.\n";
                else
                    std::cout << "Ошибка добавления (возможно, пользователь уже существует).\n";
                break;
            }
            case 2: {
                std::string username, password;
                std::cout << "Логин: ";
                std::getline(std::cin, username);
                std::cout << "Пароль: ";
                std::getline(std::cin, password);

                int userId = manager.authenticate(username, password);
                if (userId == -1) {
                    std::cout << "Неверный логин или пароль.\n";
                    break;
                }
                std::cout << "Авторизация успешна.\n";

                bool loggedIn = true;
                while (loggedIn) {
                    showPasswordMenu();
                    int pmChoice;
                    std::cin >> pmChoice;
                    std::cin.ignore();

                    switch (pmChoice) {
                        case 1: {
                            std::string title, url, login, pass;
                            std::cout << "Название сервиса: ";
                            std::getline(std::cin, title);
                            std::cout << "Ссылка: ";
                            std::getline(std::cin, url);
                            std::cout << "Логин: ";
                            std::getline(std::cin, login);
                            std::cout << "Пароль: ";
                            std::getline(std::cin, pass);

                            if (manager.addPassword(userId, title, url, login, pass))
                                std::cout << "Пароль добавлен.\n";
                            else
                                std::cout << "Ошибка добавления пароля.\n";
                            break;
                        }
                        case 2: {
                            auto passwords = manager.getPasswordsForUser(userId);
                            if (passwords.empty()) {
                                std::cout << "Пароли не найдены.\n";
                                break;
                            }
                            std::cout << "Список паролей:\n";
                            for (const auto& p : passwords) {
                                std::cout << "ID: " << p.id << "\n";
                                std::cout << "Название: " << p.title << "\n";
                                std::cout << "Ссылка: " << p.url << "\n";
                                std::cout << "Логин: " << p.login << "\n";
                                std::cout << "Пароль: " << p.password << "\n";
                                std::cout << "-------------------\n";
                            }
                            break;
                        }
                        case 3: {
                            int passId;
                            std::cout << "Введите ID пароля для редактирования: ";
                            std::cin >> passId;
                            std::cin.ignore();

                            std::string title, url, login, pass;
                            std::cout << "Новое название: ";
                            std::getline(std::cin, title);
                            std::cout << "Новая ссылка: ";
                            std::getline(std::cin, url);
                            std::cout << "Новый логин: ";
                            std::getline(std::cin, login);
                            std::cout << "Новый пароль: ";
                            std::getline(std::cin, pass);

                            if (manager.updatePassword(passId, title, url, login, pass))
                                std::cout << "Пароль обновлен.\n";
                            else
                                std::cout << "Ошибка обновления пароля.\n";
                            break;
                        }
                        case 4: {
                            int passId;
                            std::cout << "Введите ID пароля для удаления: ";
                            std::cin >> passId;
                            std::cin.ignore();

                            if (manager.deletePassword(passId))
                                std::cout << "Пароль удален.\n";
                            else
                                std::cout << "Ошибка удаления пароля.\n";
                            break;
                        }
                        case 5:
                            loggedIn = false;
                            break;
                        default:
                            std::cout << "Неверный пункт меню.\n";
                    }
                }
                break;
            }
            case 3: {
                auto users = manager.getAllUsers();
                if (users.empty()) {
                    std::cout << "Пользователи не найдены.\n";
                } else {
                    std::cout << "Список пользователей:\n";
                    for (const auto& u : users) {
                        std::cout << "ID: " << u.id << ", Имя: " << u.username << "\n";
                    }
                }
                break;
            }
            case 4: {
                int userId;
                std::cout << "Введите ID пользователя для удаления: ";
                std::cin >> userId;
                std::cin.ignore();

                if (manager.deleteUser(userId))
                    std::cout << "Пользователь удалён.\n";
                else
                    std::cout << "Ошибка удаления пользователя.\n";
                break;
            }
            case 5:
                running = false;
                break;
            default:
                std::cout << "Неверный пункт меню.\n";
        }
    }

    std::cout << "Выход из программы.\n";
    return 0;
}
