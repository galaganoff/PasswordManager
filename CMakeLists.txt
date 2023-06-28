# Является директивой в файле CMakeLists.txt, который используется для установки минимальной требуемой версии CMake для сборки проекта.
cmake_minimum_required (VERSION 3.8)
# Название собираемого проекта.
project ("PasswordManager")

# Добавьте источник в исполняемый файл этого проекта.
add_executable (PasswordManager "PasswordManager.cpp" "PasswordManager.h")

# Установка переменной "CMAKE_PREFIX_PATH" для указания пути к установленным библиотекам cryptopp и unofficial-sqlite3.
set(CMAKE_PREFIX_PATH "C:/vcpkg/vcpkg/installed/x64-windows/share/cryptopp")
set(CMAKE_PREFIX_PATH "C:/vcpkg/vcpkg/installed/x64-windows/share/unofficial-sqlite3")

# Используются для поиска и загрузки установленных библиотек cryptopp и unofficial-sqlite3.
find_package(cryptopp REQUIRED)
find_package(unofficial-sqlite3 REQUIRED)

# Используются для связывания цели с библиотеками cryptopp и unofficial-sqlite3.
 target_link_libraries(PasswordManager PRIVATE cryptopp::cryptopp)
 target_link_libraries(PasswordManager PRIVATE unofficial::sqlite3::sqlite3)

 # Этот код выполняет проверку версии CMake и устанавливает свойство CXX_STANDARD для цели PasswordManager на значение 20, если версия CMake больше 3.12.
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET PasswordManager PROPERTY CXX_STANDARD 20)
endif()
