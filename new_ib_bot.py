import logging
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    ConversationHandler,
)

# Структура разделов и терминов
classes = {
    "Термины": {
        "CIA Triad": "(Конфиденциальность, Целостность, Доступность)\nБазовая модель информационной безопасности:\nКонфиденциальность — защита данных от несанкционированного доступа.\nЦелостность — обеспечение точности и полноты информации.\nДоступность — обеспечение возможности доступа к информации для уполномоченных пользователей.",
        "Аутентификация": "Процесс проверки подлинности пользователя или устройства (например, по паролю, токену, биометрии).",
        "Авторизация": "Определение прав и уровня доступа пользователя после аутентификации.",
        "Аудит безопасности": "Систематическая проверка систем и процессов на соответствие стандартам безопасности и выявление уязвимостей.",
        "Уязвимость (Vulnerability)": "Слабое место в системе, которое может быть использовано злоумышленником для атаки.",
        "Эксплойт (Exploit)": "Программа или скрипт, использующий уязвимость для получения несанкционированного доступа или выполнения кода.",
        "Zero-Day (0-day)": "Уязвимость, о которой ещё не известно разработчикам и для которой нет патча.",
        "Атака социальной инженерии": "Манипулирование людьми с целью получения конфиденциальной информации или доступа.",
        "Фишинг (Phishing)": "Вид социальной инженерии: обман пользователя с целью получения логинов, паролей и другой информации через поддельные сайты или письма.",
        "Брутфорс (Brute Force)": "Перебор всех возможных комбинаций паролей или ключей для взлома.",
        "Социальная инженерия": "Комплекс методов психологического воздействия для получения доступа к информации.",
        "Риск-менеджмент": "Оценка, анализ и минимизация рисков в области информационной безопасности.",
        "Управление инцидентами": "(Incident Response) - Процедуры реагирования на инциденты безопасности: обнаружение, анализ, локализация, устранение и восстановление.",
        "Threat Intelligence": "Сбор, анализ и использование информации об актуальных угрозах и атаках.",
        "Red team": "Команда, имитирующая действия злоумышленника (атакующие).",
        "Blue team": "Команда защиты (обнаружение и реагирование на атаки).",
        "Purple team": "Взаимодействие Red и Blue для повышения эффективности защиты.",
    },
    "Инструменты и технологии": {
        "Nmap": "Сканер портов и сервисов. Позволяет обнаружить открытые порты, версии сервисов, операционные системы на удалённых хостах.",
        "Metasploit Framework": "Платформа для поиска, разработки и эксплуатации уязвимостей. Содержит обширную базу эксплойтов и полезных нагрузок.",
        "Burp Suite": "Комплексный инструмент для тестирования безопасности веб-приложений: перехват, анализ и изменение HTTP-трафика, автоматизация поиска уязвимостей.",
        "Wireshark": "Анализатор сетевого трафика. Позволяет захватывать и анализировать пакеты, выявлять аномалии и атаки.",
        "John the Ripper": "Популярный инструмент для взлома паролей методом перебора и словарных атак.",
        "Hydra": "Мощный инструмент для перебора паролей по различным протоколам (SSH, FTP, HTTP и др.).",
        "Aicrack-ng": "Набор инструментов для анализа и взлома Wi-Fi сетей (WEP, WPA, WPA2).",
        "Nikto": "Сканер веб-серверов на предмет известных уязвимостей, неправильных настроек и устаревших программных компонентов.",
        "SQLmap": "Автоматизированный инструмент для поиска и эксплуатации SQL-инъекций в веб-приложениях.",
        "Gobuster / Dirbuster": "Инструменты для поиска скрытых директорий и файлов на веб-серверах методом перебора.",
        "OWASP ZAP": "Бесплатный прокси для тестирования веб-приложений, автоматизации поиска уязвимостей и анализа трафика.",
        "Hashcat": "Один из самых быстрых инструментов для взлома паролей по хешам с использованием GPU.",
        "Msfvenom": "Генерация полезных нагрузок (payloads) для эксплуатации уязвимостей и создания шеллов.",
        "Masscan": "Очень быстрый сканер портов, способен сканировать весь интернет за считанные минуты.",
        "BeEF": "Фреймворк для атак через браузер, позволяет управлять скомпрометированными браузерами и проводить XSS-атаки.",
    },
    "Типы атак и уязвимостей": {
    "SQL Injection (SQLi)": "Внедрение вредоносных SQL-запросов через пользовательский ввод для обхода аутентификации или получения данных.",
    "Cross-Site Scripting (XSS)": "Внедрение вредоносного JavaScript-кода на веб-страницы для кражи данных, сессий и совершения атак от имени пользователя.",
    "Cross-Site Request Forgery (CSRF)": "Атака, при которой злоумышленник заставляет пользователя выполнить нежелательное действие от его имени на доверенном сайте.",
    "Remote Code Execution (RCE)": "Уязвимость, позволяющая злоумышленнику удалённо выполнять произвольный код на целевой системе.",
    "Privilege Escalation": "Получение более высоких привилегий в системе, чем было изначально разрешено.",
    "Man-in-the-Middle (MitM)": "Перехват и возможное изменение трафика между двумя сторонами без их ведома.",
    "Denial of Service (DoS/DDoS)": "Атаки, приводящие к отказу в обслуживании, перегрузке или недоступности сервиса.",
    "Buffer Overflow": "Переполнение буфера, позволяющее записывать данные за пределы выделенной памяти и выполнять вредоносный код.",
    "Directory Traversal": "Атака, позволяющая получить доступ к файлам и каталогам вне корневой директории веб-сервера.",
    "Path Traversal": "Синоним Directory Traversal — получение доступа к файловой системе вне разрешённых директорий.",
    "Command Injection": "Внедрение и выполнение команд операционной системы через уязвимые параметры ввода.",
    "Session Hijacking": "Захват и использование чужой сессии для получения несанкционированного доступа.",
    "Clickjacking": "Обман пользователя с помощью наложения невидимых элементов для выполнения нежелательных действий.",
    "LFI/RFI (Local/Remote File Inclusion)": "Включение локальных или удалённых файлов через уязвимый ввод, что может привести к выполнению кода.",
    "XML External Entity (XXE)": "Злоупотребление внешними сущностями в XML для локального раскрытия файлов или удалённого доступа.",
    "Insecure Deserialization": "Использование недостаточно проверенных сериализованных данных для выполнения произвольного кода.",
    "Zero-Day Exploit": "Использование ранее неизвестной уязвимости до появления патча.",
    "Password Spraying": "Массированная попытка входа с ограниченным набором паролей по многим аккаунтам для обхода блокировок.",
    "Phishing": "Социальная инженерия с целью украсть конфиденциальные данные через поддельные сайты или письма.",
    "Brute Force Attack": "Перебор всех вариантов паролей или ключей с целью взлома.",
    "Subdomain Takeover": "Захват неиспользуемого поддомена для размещения вредоносного контента.",
    "DNS Spoofing": "Подмена DNS-записей для перенаправления трафика на злонамеренный ресурс.",
    "Side-Channel Attack": "Анализ побочных эффектов системы для кражи криптографических ключей или данных.",
    "Race Condition": "Воспользование временными окнами между операциями для обхода безопасности.",
    "Trojan Horse": "Малоизвестный вредоносный код, замаскированный под безобидное ПО.",
    "Backdoor": "Скрытый метод обхода обычной аутентификации для удалённого доступа.",
    "Social Engineering": "Манипуляция человеком для получения доступа к системам или информации.",
    "DNS Tunneling": "Использование DNS-запросов для обхода фильтров и передачи данных скрытым каналом.",
    "ARP Spoofing": "Подмена ARP-записей для перехвата локального сетевого трафика.",
    "Credential Stuffing": "Автоматизированное использование скомпрометированных пар логинов для входа в разные сервисы.",
    "Malware": "Вредоносное программное обеспечение любого типа для компрометации систем.",
    "Exploit Kits": "Автоматизированные наборы эксплойтов для распространения вредоносного ПО.",
    "Watering Hole Attack": "Заражение популярного среди цели веб-сайта для атак на посетителей.",
    "Click Fraud": "Автоматизированное создание ложных кликов для мошенничества в рекламе.",
    "Eavesdropping": "Перехват конфиденциальных данных в сети без модификации.",
    "Keylogger": "Программа или устройство для записи нажатий клавиш с целью кражи паролей.",
    "DNS Amplification": "Вид DDoS-атаки, в которой злоумышленник использует DNS-серверы для увеличения объёма трафика.",
    "Logic Bomb": "Вредоносный код, активирующийся при наступлении определённых условий.",
    "Firmware Attack": "Атака на низкоуровневое программное обеспечение (прошивку) устройств.",
    "Click Fraud": "Автоматизированное создание ложных кликов в рекламе для финансовой выгоды.",
    "OAuth Token Theft": "Кража токенов доступа для обхода аутентификации.",
    "HTML Injection": "Внедрение вредоносного HTML в страницы для обмана и фишинга.",
    "File Upload Vulnerability": "Загрузка вредоносных файлов на сервер для дальнейшего выполнения атак.",
    "Insider Threat": "Опасность, исходящая от сотрудников или пользователей с доступом к системе.",
    "Password Cracking": "Взлом паролей с помощью различных методов, включая словарные и радужные таблицы.",
    "API Abuse": "Неправомерное использование API для обхода безопасности или получения данных.",
    "Memory Corruption": "Ошибки управления памятью, приводящие к исполнению кода или сбоям.",
    "Sandbox Escape": "Атаки, которые позволяют выйти из изолированной среды исполнения и получить доступ к системе.",
    "TLS/SSL Stripping": "Атака, снижающая защиту HTTPS-соединения до незашифрованного HTTP.",
    "Clickjacking": "Манипуляция элементами страницы для обмана пользователя и запуска нежелательных действий."
    },
    "Сетевые и крипто технологии": {
        "VPN (Virtual Private Network)": "Технология для создания защищённого канала связи поверх незащищённой сети (например, интернет).",
        "Firewall (Межсетевой экран)": "Аппаратное или программное средство для фильтрации сетевого трафика по заданным правилам.",
        "IDS/IPS": "(Intrusion Detection/Prevention System) - Системы обнаружения и предотвращения вторжений: анализируют трафик и реагируют на подозрительную активность.",
        "TLS/SSL": "Криптографические протоколы для защиты передачи данных в интернете (например, HTTPS).",
        "PKI": " (Public Key Infrastructure) - Инфраструктура открытых ключей: система управления цифровыми сертификатами и ключами.",
        "Hash-функции (SHA, MD5 и др.)": "Алгоритмы для преобразования данных в фиксированный по длине хеш-отпечаток, используются для проверки целостности.",
        "Симметричное шифрование": "один ключ для шифрования и дешифрования (AES, DES).",
        "Асимметричное шифрование": "пара открытого и закрытого ключей (RSA, ECC).",
        "JWT (JSON Web Token)": "Компактный формат для безопасной передачи информации между сторонами как JSON-объект, часто используется для авторизации.",
        "X.509 Certificate": "Стандарт цифровых сертификатов, используемых для идентификации и шифрования в сетях.",
    },
    "Стандарты, процессы и фреймы": {
        "OWASP Top 10": "Список из 10 самых критичных уязвимостей веб-приложений по версии OWASP, обновляется регулярно.",
        "MITRE ATT&CK": "База знаний тактик, техник и процедур злоумышленников, используется для анализа и моделирования угроз.",
        "NIST (National Institute of Standards and Technology)": "Американский институт стандартов, разрабатывающий рекомендации и стандарты по кибербезопасности (например, NIST SP 800-53).",
        "ISO/IEC 27001": "Международный стандарт по управлению информационной безопасностью (ISMS).",
        "SOC": "(Security Operations Center) - Центр мониторинга и реагирования на инциденты безопасности в организации.",
        "Vulnerability Assessment": "Процесс поиска и оценки уязвимостей в системах и приложениях.",
        "Penetration Testing (Pentest)": "Эмуляция атак для поиска уязвимостей и проверки защищённости систем.",
        "Sandboxing": "Изоляция процессов или приложений для предотвращения распространения вредоносного кода.",
        "Forensic Analysis": "Комплекс методов для расследования инцидентов, сбора и анализа цифровых доказательств.",
    },
}

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

SECTION, TERM = range(2)
TERMS_PER_PAGE = 10


async def show_sections(update: Update, context: ContextTypes.DEFAULT_TYPE):
    reply_markup = ReplyKeyboardMarkup(
        [[k] for k in classes.keys()], resize_keyboard=True
    )
    await update.message.reply_text(
        "Выберите раздел для изучения:", reply_markup=reply_markup
    )
    return SECTION


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    reply_markup = ReplyKeyboardMarkup(
        [[k] for k in classes.keys()], resize_keyboard=True
    )
    await update.message.reply_text(
        "Привет! Я бот по информационной безопасности. Выберите раздел для изучения:",
        reply_markup=reply_markup,
    )
    return SECTION


def get_terms_page(terms, page):
    start = page * TERMS_PER_PAGE
    end = start + TERMS_PER_PAGE
    return terms[start:end]


def get_total_pages(terms):
    return (len(terms) - 1) // TERMS_PER_PAGE + 1


async def section(update: Update, context: ContextTypes.DEFAULT_TYPE):
    section = update.message.text
    if section not in classes:
        await update.message.reply_text("Пожалуйста, выберите раздел с помощью кнопок.")
        return SECTION
    context.user_data["section"] = section
    context.user_data["page"] = 0
    return await show_terms(update, context)


async def show_terms(update: Update, context: ContextTypes.DEFAULT_TYPE):
    section = context.user_data["section"]
    page = context.user_data.get("page", 0)
    terms = list(classes[section].keys())
    total_pages = get_total_pages(terms)
    page = max(0, min(page, total_pages - 1))
    context.user_data["page"] = page
    terms_page = get_terms_page(terms, page)
    keyboard = [[term] for term in terms_page]
    nav_buttons = []
    if total_pages > 1:
        if page > 0:
            nav_buttons.append("⬅️ Назад")
        if page < total_pages - 1:
            nav_buttons.append("Вперёд ➡️")
    nav_buttons += ["Обратно", "Разделы"]
    keyboard.append(nav_buttons)
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        f"Раздел: {section}\nВыберите термин (стр. {page+1}/{total_pages}):",
        reply_markup=reply_markup,
    )
    return TERM


async def term(update: Update, context: ContextTypes.DEFAULT_TYPE):
    section = context.user_data.get("section")
    page = context.user_data.get("page", 0)
    term = update.message.text
    terms = list(classes[section].keys())
    total_pages = get_total_pages(terms)
    if term == "Обратно":
        return await show_terms(update, context)
    if term == "Разделы":
        return await show_sections(update, context)
    if term == "⬅️ Назад":
        context.user_data["page"] = max(0, page - 1)
        return await show_terms(update, context)
    if term == "Вперёд ➡️":
        context.user_data["page"] = min(total_pages - 1, page + 1)
        return await show_terms(update, context)
    if section not in classes or term not in classes[section]:
        await update.message.reply_text("Пожалуйста, выберите термин с помощью кнопок.")
        return TERM
    text = f"<b>{term}</b>\n{classes[section][term]}"
    # Разбиваем длинный текст на части по 4096 символов
    max_len = 4096
    parts = [text[i : i + max_len] for i in range(0, len(text), max_len)]
    for part in parts:
        await update.message.reply_text(part, parse_mode="HTML")
    reply_markup = ReplyKeyboardMarkup([["Обратно", "Разделы"]], resize_keyboard=True)
    await update.message.reply_text("Выберите действие:", reply_markup=reply_markup)
    return TERM


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("До встречи!", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


def main():
    import os

    TOKEN = os.getenv("TELEGRAM_TOKEN") or "8141597316:AAF1qM2GG6ku_D0pJCe5bF_nutG-LULaOiA"
    app = ApplicationBuilder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            SECTION: [MessageHandler(filters.TEXT & ~filters.COMMAND, section)],
            TERM: [MessageHandler(filters.TEXT & ~filters.COMMAND, term)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    app.add_handler(conv_handler)
    print("Бот запущен. Нажмите Ctrl+C для остановки.")
    app.run_polling()


if __name__ == "__main__":
    main()
