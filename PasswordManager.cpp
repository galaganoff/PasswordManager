// Подключение заголовочного файла
#include "PasswordManager.h"
// Объявляю глобальные переменные для работы с логином и паролей пользователя
// Логин пользователя для входа в систему "Менеджера паролей"
std::string loginToCheck;
// Пароль пользователя для входа в систему "Менеджера паролей"
std::string passwordToInsert;
// Эта директива проверяет, определен ли макрос _WIN32. 
#ifdef _WIN32
// Если макрос _WIN32 определен, то в этой ветви CLEAR_COMMAND будет определен как строковый литерал "cls". "cls" является командой в командной строке Windows, которая очищает экран.
#define CLEAR_COMMAND "cls"
// Если макрос _WIN32 не определен
#else
// В этой ветви CLEAR_COMMAND определен как строковый литерал "clear". "clear" является командой в Unix-подобных операционных системах (например, Linux, macOS), которая также очищает экран.
#define CLEAR_COMMAND "clear"
#endif
// Директива using namespace CryptoPP; используется для объявления пространства имен CryptoPP как текущего пространства имен.
using namespace CryptoPP;
// Функция, прр помощи которой осуществляется зашифрование пароля пользователя.
std::string EncryptPassword(const std::string& password, const std::string& masterPassword)
{   // encryptedPassword - строка, которая будет содержать зашифрованный пароль.
    std::string encryptedPassword;

    // Хэшируем мастер-пароль с помощью SHA256
    SHA256 sha256;
    byte masterPasswordHash[SHA256::DIGESTSIZE];
    /* Это экземпляр объекта класса SHA256.
    CalculateDigest - это метод класса SHA256, который используется для вычисления хэша. Он принимает несколько аргументов:
    masterPasswordHash - это переменная (или массив), куда будет записан полученный хэш.
    reinterpret_cast<const byte*>(masterPassword.data()) - это приведение типа указателя на байт, которое позволяет передать данные мастер-пароля в метод CalculateDigest. masterPassword.data() возвращает указатель на данные мастер-пароля.
    masterPassword.size() - это размер данных мастер-пароля. */
    sha256.CalculateDigest(masterPasswordHash, reinterpret_cast<const byte*>(masterPassword.data()), masterPassword.size());

    //Создаем ключ для шифрования из хэша мастер-пароля
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    memcpy(key, masterPasswordHash, key.size());
    // Заимствование CryptoPP/aes начало
    try
    {
        // Инициализируем шифр AES с использованием ключа.
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), key);

        // Шифруем пароль
        StringSource(password, true,
            new StreamTransformationFilter(encryption,
                new HexEncoder(
                    new StringSink(encryptedPassword)
                )
            )
        );
    }
    catch (const Exception& e)
    {
        // Используется для вывода сообщения об ошибке.
        std::cerr << "Encryption error: " << e.what() << std::endl;
    }
    // Заимствование CryptoPP/aes конец
    // Возвращение зашифрованного пароля в формате строки.
    return encryptedPassword;
}
// Функция, прр помощи которой осуществляется расшифрование пароля пользователя.
std::string DecryptPassword(const std::string& encryptedPassword, const std::string& masterPassword)
{   // decryptedPassword - строка, которая будет принимать значения расшифрованных паролей.
    std::string decryptedPassword;

    // Хэшируем мастер-пароль с помощью SHA256
    SHA256 sha256;
    byte masterPasswordHash[SHA256::DIGESTSIZE];
    sha256.CalculateDigest(masterPasswordHash, reinterpret_cast<const byte*>(masterPassword.data()), masterPassword.size());

    // Создаем ключ для расшифровки из хэша мастер-пароля
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    memcpy(key, masterPasswordHash, key.size());
    // Заимствование CryptoPP/aes начало
    try
    {
        // Инициализируем шифр AES с использованием ключа
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size(), key);

        // Расшифровываем пароль
        StringSource(encryptedPassword, true,
            new HexDecoder(
                new StreamTransformationFilter(decryption,
                    new StringSink(decryptedPassword)
                )
            )
        );
    }
    catch (const Exception& e)
    {
        // Используется для вывода сообщения об ошибке.
        std::cerr << "Decryption error: " << e.what() << std::endl;
    }
    // Заимствование CryptoPP/aes конец
    // Возвращиние расшифрованного пароля в формате строки.
    return decryptedPassword;
}
// Функция генерации пароля. length - длинна пароля всимволах. includeSpecialChars - используется для определения необходимости использования уникальных символов.
std::string generatePassword(int length, bool includeSpecialChars) {
    /* password - строка, которая будет использоваться для хранения созданного пароля.
    characters - алфавит, состоящий из символов английского языка, используется для создания пароля. */
    std::string password;
    std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // Реализация возможности использовать символы при создании пароля.
    if (includeSpecialChars) {
        // Добавляет в используемый для генерации пароля алфавит символы.
        characters += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    }
    // Функция стандартной библиотеки c++, используется для генерации случайного числа с использованием текущего времени без какиз-либо сдвигов.
    srand(time(0));
    // Цикл, в котором пока длинна сгенерированного пароля не достигнет длинны заданной пользователем, в пароль будут добавлятся случайные символы из алфавита.
    for (int i = 0; i < length; ++i) {
        int randomIndex = rand() % characters.length();
        password += characters[randomIndex];
    }
    // Возвращает созданный пароль.
    return password;
}
// Функция оценки сложности пароля. Учитывает ряд оценочных критериев, оценка выставляется по сумме набранных быллов. На вход принимает пароль.
int estimatePasswordStrength(const std::string& password) {
    // Длинна пароля.
    int length = password.length();
    // Стартовый счет. 
    int score = 0;
    // Оценка длинны пароля.
    if (length >= 8) {
        score += 5;
    }
    // Оценка длинны пароля.
    if (length >= 16) {
        score += 5;
    }
    // Создание логических переменных для проверки наличия разных видов символов.
    bool hasLowercase = false;
    bool hasUppercase = false;
    bool hasDigit = false;
    bool hasSpecialChar = false;

    for (char c : password) {
        if (islower(c)) {
            hasLowercase = true;
        }
        else if (isupper(c)) {
            hasUppercase = true;
        }
        else if (isdigit(c)) {
            hasDigit = true;
        }
        else if (std::string("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~").find(c) != std::string::npos) {
            hasSpecialChar = true;
        }
    }
    // Начисление очков за разнообразие используемых разновидностей символов. Наличие строчных символов.
    if (hasLowercase) {
        score += 5;
    }
    // Начисление очков за разнообразие используемых разновидностей символов. Наличие символов верхнего регистра.
    if (hasUppercase) {
        score += 5;
    }
    // Начисление очков за разнообразие используемых разновидностей символов. Наличие цифр.
    if (hasDigit) {
        score += 5;
    }
    // Начисление очков за разнообразие используемых разновидностей символов. Наличие char - символов.
    if (hasSpecialChar) {
        score += 5;
    }
    // Возвращает полученную оценку.
    return score;
}
// Функция, использующаяся для очистки коммандной консоли. 
void clearConsole() {
    std::system(CLEAR_COMMAND);
}
// Функция для характеристики пароля по его сложности.
std::string passworddiffencerank(int score) {
    // rank - возвращает текстовую оценку сложности пароля. 
    std::string rank;
    clearConsole();
    // Невероятно слабый пароль
    if (score >= 0 && score <= 5) {
        rank = "incredibly easy";
    } 
    // Очень слабый пароль
    if (score >= 6 && score <= 10) {
        rank = "very easy";
    } 
    // Слабый пароль
    if (score >= 11 && score <= 15) {
        rank = "easy";
    }
    //  Средний по сложности пароль
    if (score >= 16 && score <= 20) {
        rank = "medium";
    }
    // Надежный пароль пароль
    if (score >= 21 && score <= 25) {
        rank = "strong";
    }
    // Очень надежный пароль
    if (score >= 26 && score <= 30) {
        rank = "very strong";
    }
    // Возвращение полученной текстовой характеристки.
    return rank;
}
// Функция, которая реализует подведение итого оценки сложности пароля и дает рекоммендации по поводу пароля.
void printPasswordRecommendation(int score,std::string rank) {
    clearConsole();
    // Слабые пароли, которые необходимо менять в срочном порядке.
    if (score >= 0 && score <= 10) {
        std::cout << "Оценка надежности пароля: " << score << " из 30. Пароль " << rank << " сложности, срочно нужно менять!" << std::endl;
    }
    // Пароли средней сложности, которые рекомендуется усилить.
    else if (score >= 11 && score <= 20) {
        std::cout << "Оценка надежности пароля: " << score << " из 30. Пароль " << rank << " сложности, рекомендуется усилить его!" << std::endl;
    }
    // Надежные пароли.
    else if (score >= 21 && score <= 30) {
        std::cout << "Оценка надежности пароля: " << score << " из 30. Пароль " << rank << " сложности. Хороший пароль!" << std::endl;
    }

    std::cout << std::endl; // Выводит пустую строку.
    std::cout << "Нажмите Enter, чтобы продолжить..."; // Выводит сообщение.
    std::cin.ignore(); // Игнорированые введенных команд.
    std::cin.get(); // Ожидание, пока пользователь не нажмет на "ENTER"
    clearConsole(); // Очистка консоли.
}
// Функция, которая используется для взаимодействия с пользователем. На вход поступают Логин и Пароль пользователя для авторизации в приложении.
void getInputValues() {
    // Логин пользователя.
    std::cout << "Введите значение для столбца 'login': ";
    std::cin >> loginToCheck;
    // Пароль пользователя.
    std::cout << "Введите значение для столбца 'password': ";
    std::cin >> passwordToInsert;
}
// Функция, используется для тестирования функции "EncryptPasswor".
void Test_EncryptPassword() {
    assert(EncryptPassword("password", "asd") == "D665129A510299142318460569C26793");
    assert(EncryptPassword("password", "Qwerty") == "DAEEDD15E2EA9A0716ED0229F8B91937");
    assert(EncryptPassword("qwertypogchamp", "pass") == "10D2EF9A3FE6ED6A378FE3F44EA44413");
    assert(EncryptPassword("nodatapass123123", "CrypTo") == "8E527E3D7DD00A875E94082CDA820A03FD167BACBBF59873523707CD01229BC9");
    assert(EncryptPassword("_ha-rdpa-sswo-rd113_", "secret") == "59CA744186F71140E2FD34E77376DED233173F7C794EED0A98692DEE0C457097");
    std::cout << "Test_EncryptPassword OK" << std::endl;
    clearConsole();
}
// Функция, используется для тестирования функции "estimatePasswordStrengt".
void Test_estimatePasswordStrength() {
    assert(estimatePasswordStrength("Qwerty") == 10);
    assert(estimatePasswordStrength("asd") == 5);
    assert(estimatePasswordStrength("123456124") == 10);
    assert(estimatePasswordStrength("password!2345") == 20);
    assert(estimatePasswordStrength("password") == 10);
    assert(estimatePasswordStrength("UAhxdndusa*^Z26ja--") == 30);
    assert(estimatePasswordStrength("poiuydSa233") == 20);
    assert(estimatePasswordStrength("cat") == 5);
    assert(estimatePasswordStrength("876") == 5);
    std::cout << "Test_estimatePasswordStrength OK" << std::endl;
    clearConsole();
}
// Функция, используется для тестирования функции "passworddiffencerank".
void Test_passworddiffencerank() {
    assert(passworddiffencerank(0) == "incredibly easy");
    assert(passworddiffencerank(2) == "incredibly easy");
    assert(passworddiffencerank(6) == "very easy");
    assert(passworddiffencerank(13) == "easy");
    assert(passworddiffencerank(19) == "medium");
    assert(passworddiffencerank(30) == "very strong");
    assert(passworddiffencerank(24) == "strong");
    std::cout << "Test_passworddiffencerank OK" << std::endl;
    clearConsole();
}
// Начало основной части "main"
int main() {
    // Используется для установки локали (региональных настроек) в программе на русский язык.
    setlocale(LC_ALL, "Russian");
    // Вызов функций тестирования.
    Test_estimatePasswordStrength();
    Test_EncryptPassword();
    Test_passworddiffencerank();
    // Представляет объявление указателя db на объект типа sqlite3, используемого для работы с базой данных SQLite.
    sqlite3* db;

    int rc;

    // Создаем базу данных
    rc = sqlite3_open("passsec.db", &db);
    if (rc) {
        std::cerr << "Не удалось создать базу данных: " << sqlite3_errmsg(db) << std::endl;
        return rc;
    }

    // Создаем таблицу "passwordtb", если она не существует.
    std::string createTableSQL = "CREATE TABLE IF NOT EXISTS passwordd ("
        // Логин пользователя, используется для авторизации в приложении.
        "login TEXT, "
        // Пароль пользователь, используется для авторизации в приложении.
        "password TEXT, "
        // Название портала/приложения/мессенджера.
        "wname TEXT, "
        // Логин пользователя, используется для авторизации на сторонних ресурсах.
        "wlogin TEXT, "
        // Пароль пользователя, используется для авторизации на сторонних ресурсах и хранится в зашифрованном виде.
        "rpasswordsf TEXT"
        ");";

    rc = sqlite3_exec(db, createTableSQL.c_str(), 0, 0, 0);
    // Указывает на успешно выполнение запроса.
    if (rc != SQLITE_OK) {
        std::cerr << "Ошибка при выполнении SQL-запроса: " << sqlite3_errmsg(db) << std::endl;
        // Закрытие соединения с БД.
        sqlite3_close(db);
        return rc;
    }
    // Числовая переменная, будет использоваться для управления приложением пользователем.
    int choice;
    // Цикл, при котором программа перестает работать, только если пользователь решает сам выйти из приложения.
    while (true) {
        // Главное меню.
        std::cout << "Что вы хотите сделать?" << std::endl;
        std::cout << "1. Зарегистрироваться" << std::endl;
        std::cout << "2. Войти" << std::endl;
        std::cout << "3. Сгенерировать пароль" << std::endl;
        std::cout << "4. Оценить надежность пароля" << std::endl;
        std::cout << "5. Выйти из программы" << std::endl;
        std::cout << "Введите номер выбранного действия: ";
        // Принимаем ответ пользователя.
        std::cin >> choice;
        clearConsole();
        // Если пользователь хочет зарегистрироваться.
        if (choice == 1) {
            clearConsole();
            std::cout << "Вы выбрали зарегистрироваться." << std::endl;
            std::cout << std::endl;
            // Создание переменных типа string, для дальнейшего их использования.
            std::string login;
            std::string password;
            // Переменная login принимает значение логина пользователя.
            std::cout << "Введите логин: ";
            std::cin >> login;
            // Переменная password принимает значение пароля пользователя.
            std::cout << "Введите пароль: ";
            std::cin >> password;

            // Экранируем символы во входных значениях.
            std::string escapedLogin = sqlite3_mprintf("%q", login.c_str());
            std::string escapedPassword = sqlite3_mprintf("%q", password.c_str());

            // Проверка наличия значения login в базе данных.
            std::string selectLoginSQL = "SELECT login FROM passwordd WHERE login = '" + escapedLogin + "';";
            bool loginExists = false;
            rc = sqlite3_exec(db, selectLoginSQL.c_str(), [](void* data, int argc, char** argv, char** /*columnNames*/) -> int {
                bool* loginExists = static_cast<bool*>(data);
            if (argc > 0 && argv[0]) {
                *loginExists = true;
            }
            return 0;
                }, &loginExists, 0);

            if (rc != SQLITE_OK) {
                std::cerr << "Ошибка при выполнении SQL-запроса: " << sqlite3_errmsg(db) << std::endl;
                sqlite3_close(db);
                return rc;
            }
            // В случае, если пользователь уже зарегистрирован или его login уже кто-то занял.
            if (loginExists) {
                std::cout << "Пользователь с таким логином уже существует." << std::endl;
            }
            else {
                // Добавление login и password в базу данных
                std::string insertUserSQL = "INSERT INTO passwordd (login, password) VALUES ('" + escapedLogin + "', '" + escapedPassword + "');";
                rc = sqlite3_exec(db, insertUserSQL.c_str(), 0, 0, 0);
                if (rc != SQLITE_OK) {
                    std::cerr << "Ошибка при выполнении SQL-запроса для добавления пользователя: " << sqlite3_errmsg(db) << std::endl;
                    sqlite3_close(db);
                    return rc;
                }
                std::cout << "Регистрация успешно завершена." << std::endl;
            }

            std::cout << std::endl;
            std::cout << "Нажмите Enter, чтобы продолжить...";
            std::cin.ignore();
            std::cin.get();
            clearConsole();
        }
        // Если пользователь решил авторизоваться.
        else if (choice == 2) {
            clearConsole();
            std::cout << "Вы выбрали войти в систему." << std::endl;
            std::cout << std::endl;
            // Создание переменных типа string, для авторизации пользователя с приложении.
            std::string login;
            std::string password;
            // Пользователь вводит логин, используемый для авторизации в проложении.
            std::cout << "Введите логин: ";
            std::cin >> login;
            // Пользователь вводит пароль, используемый для авторизации в проложении.
            std::cout << "Введите пароль: ";
            std::cin >> password;

            // Экранируем символы во входных значениях
            std::string escapedLogin = sqlite3_mprintf("%q", login.c_str());
            std::string escapedPassword = sqlite3_mprintf("%q", password.c_str());

            // Проверка наличия значения login и password в базе данных
            std::string selectUserSQL = "SELECT * FROM passwordd WHERE login = '" + escapedLogin + "' AND password = '" + escapedPassword + "';";
            bool userExists = false;
            rc = sqlite3_exec(db, selectUserSQL.c_str(), [](void* data, int argc, char** argv, char** /*columnNames*/) -> int {
                bool* userExists = static_cast<bool*>(data);
            if (argc > 0 && argv[0]) {
                *userExists = true;
            }
            return 0;
                }, &userExists, 0);

            if (rc != SQLITE_OK) {
                std::cerr << "Ошибка при выполнении SQL-запроса: " << sqlite3_errmsg(db) << std::endl;
                sqlite3_close(db);
                return rc;
            }

            if (!userExists) {
                // Ошибка, возникающая в случае, если заданный пользователем логин и пароль не были найдены в БД. 
                std::cout << "Неправильный логин или пароль." << std::endl;
                std::cout << std::endl;
                std::cout << "Нажмите Enter, чтобы продолжить...";
                std::cin.ignore();
                std::cin.get();
                clearConsole();
            }
            else {
                // Оповещение о удавшейся авторизации пользователя.
                std::cout << "Вход выполнен успешно." << std::endl;
                std::cout << std::endl;
                // Появление нового меню взоимодейсчтвия. 
                std::cout << "Выберите действие:" << std::endl;
                std::cout << "1. Добавить пароль" << std::endl;
                std::cout << "2. Показать мои пароли" << std::endl;
                // Числовая переменная типа int, принимает значения - ответы пользователя для взаимодействия с открытым разделом меню.
                int innerChoice;
                std::cout << "Введите номер действия: ";
                // переменная приниает команду, заданную пользователем.
                std::cin >> innerChoice;
                // Пользователь решил сохранить новый пароль. 
                if (innerChoice == 1) {
                    // Переменный, необходимые для принятия данных от пользователя и в дальнейшем сохранения данных пользователя в БД.
                    // Тип string, принимает на вход наименование ресурса.
                    std::string rname;
                    // Тип string, принимает на вход легой, используемый пользователем для авторизации на стороннем ресурсе.
                    std::string rlogin;
                    // Тип string, принимает на вход пароль, используемый для авториззации на стороннем ресурсе..
                    std::string rpasswordsf;
                    // Тип string, принимает на мастер-пароль для зашифрования пароля пользователя..
                    std::string masterPassword;
                    
                    std::cout << "Введите название ресурса: ";
                    // Принимаем название ресурса.
                    std::cin >> rname;

                    std::cout << "Введите логин от ресурса: ";
                    // Принимаем логин пользователдя.
                    std::cin >> rlogin;

                    std::cout << "Введите пароль от ресурса: ";
                    // Принимаем пароль пользователя.
                    std::cin >> rpasswordsf;

                    std::cout << "Введите мастер-пароль: ";
                    // Принимаем мастер-пароль.
                    std::cin >> masterPassword;
                    // Зашифрование пароля с использованием мастер-пароля.
                    std::string encryptedPassword = EncryptPassword(rpasswordsf, masterPassword);

                    std::string escapedRname = sqlite3_mprintf("%q", rname.c_str());
                    std::string escapedRlogin = sqlite3_mprintf("%q", rlogin.c_str());
                    std::string escapedRpasswordsf = sqlite3_mprintf("%q", rpasswordsf.c_str());
                    // Новые данные пользователя добавляются в БД.
                    std::string insertPasswordSQL = "INSERT INTO passwordd (login, password, wname, wlogin, rpasswordsf) VALUES ('" + escapedLogin + "', '" + escapedPassword + "', '" + escapedRname + "', '" + escapedRlogin + "', '" + encryptedPassword + "');";
                    rc = sqlite3_exec(db, insertPasswordSQL.c_str(), 0, 0, 0);

                    if (rc != SQLITE_OK) {
                        std::cerr << "Ошибка при выполнении SQL-запроса для добавления пароля: " << sqlite3_errmsg(db) << std::endl;
                        sqlite3_close(db);
                        return rc;
                    }
                    // Сообщение, подтверждающее, что данные были успешно занесены в БД.
                    std::cout << "Пароль успешно добавлен." << std::endl;
                }
                // Если пользователь хочет увидеть свои пароли.
                if (innerChoice == 2) {
                    // Показать пароли
                    std::vector<std::string> passwords;
                    // Запрос к Бд для получения все данных о польхователе.
                    std::string selectPasswordsSQL = "SELECT wname, wlogin, rpasswordsf FROM passwordd WHERE login = '" + escapedLogin + "' AND password = '" + escapedPassword + "';";
                    rc = sqlite3_exec(db, selectPasswordsSQL.c_str(), [](void* data, int argc, char** argv, char** /*columnNames*/) -> int {
                        std::vector<std::string>* passwords = static_cast<std::vector<std::string>*>(data);
                    for (int i = 0; i < argc; i += 3) {
                        if (argv[i] && argv[i + 1] && argv[i + 2]) {
                            std::string masterPassword;
                            // Пользователь далжен ввести мастер-пароль для расшифрования смоего пароля от ресурса. Мастер-пароль не храница в приложении, при его утере данные невозможно расшифровать.
                            std::cout << "Введите мастер-пароль: ";
                            // Мастер-пароль вводится пользователем для каждого пароля отдель, это призванно повысить защищенность данных.
                            std::cin >> masterPassword;
                            // Расшифрование пароля пользователя с использованием мастер-пароля.
                            std::string decryptedPassword = DecryptPassword(argv[i + 2], masterPassword);
                            std::string output = argv[i] + std::string(" ") + argv[i + 1] + std::string(": ") + decryptedPassword;
                            passwords->push_back(output);
                        }
                    }
                    return 0;
                        }, &passwords, 0);

                    if (rc != SQLITE_OK) {
                        std::cerr << "Ошибка при выполнении SQL-запроса для получения паролей: " << sqlite3_errmsg(db) << std::endl;
                        sqlite3_close(db);
                        return rc;
                    }
                    // Вывод массива паролей
                    for (const std::string& password : passwords) {
                        std::cout << password << std::endl;
                    }
                }
            }
        }
        // Генерация пароля.
        else if (choice == 3) {
            clearConsole();
            std::cout << "Вы выбрали сгенерировать пароль." << std::endl;
            // Переменная типа int, отвеает за желаемую длинну пароля.
            int passwordLength;
            std::cout << "Введите длину пароля: ";
            // Длинна пароля - задается пользователем.
            std::cin >> passwordLength;
            // переменная типа int - отвечает за наличие в пароле char - символов.
            int includeSpecialCharsChoice;
            std::cout << "Можно ли использовать специальные символы? (1 - Да, 2 - Нет): ";
            // Информация о налиции char - сиволов в пароле.
            std::cin >> includeSpecialCharsChoice;
            // переменная типа string - используется для хранения сгенерированног пароля.
            std::string generatedPassword;
            bool includeSpecialChars;
            // Генерация пароля с использованием char - символов.
            if (includeSpecialCharsChoice == 1) {
                includeSpecialChars = true;
                // Функция генерации пароля.
                generatedPassword = generatePassword(passwordLength, includeSpecialChars);
                // Вывод сгенерированного пароля.
                std::cout << "Сгенерированный пароль: " << generatedPassword << std::endl;
            }
            // Генерация пароля с без использования char - символов.
            else if (includeSpecialCharsChoice == 2) {
                includeSpecialChars = false;
                // Функция генерации пароля.
                generatedPassword = generatePassword(passwordLength, includeSpecialChars);
                // Вывод сгенерированного пароля.
                std::cout << "Сгенерированный пароль: " << generatedPassword << std::endl;
            }
            else {
                // Ошибка, возникает в случаеЮ когда пользователь вводит некорректную команду.
                std::cout << "Некорректная команда. Пожалуйста, выберите 1 или 2." << std::endl;
            }

            std::cout << std::endl;
            std::cout << "Нажмите Enter, чтобы продолжить...";
            std::cin.ignore();
            std::cin.get();
            clearConsole();
        }
        // Оценка надежности пароля.
        else if (choice == 4) {
            clearConsole();
            std::cout << "Вы выбрали оценить надежность пароля." << std::endl;
            // переменная типа string - используется для получения пароля пользователя, для дальнейшей оценки надежности пароля.
            std::string password;
            std::cout << "Введите пароль: ";
            // Пользователь вводит пароль.
            std::cin >> password;
            // Оценка сложности пароля по набранным балла, переменная типа int.
            int strength = estimatePasswordStrength(password);
            // Текстовая оценочная характеристика надежности пароля пользователя.
            std::string rank = passworddiffencerank(strength);
            // Сообщение пользователю с обеими оценками и рекомендации по дальнейшему использованию исследумоего пароля.
            printPasswordRecommendation(strength, rank);
        }
        // Выход из приложения.
        else if (choice == 5) {
            clearConsole();
            std::cout << "Вы выбрали выйти из программы. До свидания!" << std::endl;
            // Остановка работы программы.
            break;
        }
        // Ошибка, возникает в случаях использвания некорректных команд пользователем.
        else {
            std::cout << "Некорректная команда. Пожалуйста, выберите действие из предложенных вариантов." << std::endl;
            std::cout << std::endl;
            std::cout << "Нажмите Enter, чтобы продолжить...";
            std::cin.ignore();
            std::cin.get();
        }
    }

    // Закрываем соединение с базой данных
    sqlite3_close(db);

    return 0;
}
