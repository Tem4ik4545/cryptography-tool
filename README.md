Криптопровайдер (Cryptography Tool)

Описание
Криптопровайдер — это приложение, разработанное для выполнения различных криптографических операций, таких как генерация ключей, шифрование и расшифрование файлов и текста, цифровая подпись и проверка целостности данных. Этот инструмент предоставляет гибкий интерфейс для работы с симметричными и асимметричными алгоритмами шифрования.

Функционал
1. Управление ключами
Генерация RSA ключей (публичный и приватный ключи) с шифрованием приватного ключа на основе пароля.
Удаление ключей из защищенного контейнера.

2. Шифрование и расшифрование
-Алгоритмы:
AES: Симметричное шифрование с использованием пароля.
RSA: Асимметричное шифрование с использованием публичного и приватного ключей.

-Функционал:
Шифрование/расшифрование текстов.
Шифрование/расшифрование файлов.

3. Цифровая подпись
Вычисление хэшсуммы файла (SHA-256).
Создание цифровой подписи файла с использованием RSA и генерация X.509-сертификата.
Проверка подписи файла для подтверждения его целостности.

Установка
Требования:
Python 3.9+
Установленные зависимости из requirements.txt.

Установка:
1.Клонируйте репозиторий или скачайте проект.

2.Установите зависимости:
pip install -r requirements.txt

3.Запустите сервер API:
uvicorn app.main:app --reload

4.Запустите клиентское приложение:
python main_window.py


Использование
1. Генерация ключей
Введите имя ключа и пароль для его защиты.
Нажмите "Generate Keys" для создания пары ключей (публичного и приватного).
Ключи сохраняются в защищенном контейнере.

2. Удаление ключей
Укажите имя ключа и пароль.
Нажмите "Delete Key" для удаления ключа из контейнера.

3. Шифрование/расшифрование текста
Выберите алгоритм (AES или RSA).
Для AES: Введите пароль.
Для RSA: Укажите имя ключа и пароль.
Введите текст и нажмите "Encrypt Text" для шифрования или "Decrypt Text" для расшифрования.

4. Шифрование/расшифрование файлов
Выберите файл.
Выберите алгоритм (AES или RSA).
Для AES: Введите пароль.
Для RSA: Укажите имя ключа и пароль.
Нажмите "Encrypt File" или "Decrypt File".

5. Цифровая подпись
Выберите файл для подписи.
Укажите имя ключа и пароль.
Нажмите "Sign File". Будут созданы:
Файл подписи (.sig).
Сертификат X.509 (.cert).
Для проверки подписи выберите исходный файл. Программа автоматически использует .sig и .cert из той же директории.
Нажмите "Verify File Signature". Результат проверки будет выведен в интерфейсе.

Пример работы
Генерация ключей:
Имя ключа: test_key
Пароль: password123

Шифрование текста:
Алгоритм: AES
Пароль: mypassword
Исходный текст: Пример текста
Зашифрованный текст: a1b2c3...

Создание цифровой подписи:
Исходный файл: example.txt
Подпись: example.txt.sig
Сертификат: example.txt.cert

Ограничения RSA: Максимальный размер данных для RSA шифрования зависит от длины ключа.

Контакты
Автор: [by tem4ick4545]
Email: [artem_veryutin@mail.ru]