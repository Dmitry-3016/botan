import json
import os
from datetime import time
import logging
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
    ConversationHandler,
    CallbackContext,
)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)

ENTER_HABIT, ENTER_TIME = range(2)

main_keyboard = [["Мои привычки", "Новая привычка"]]
cancel_keyboard = [["Отмена"]]

reply_main = ReplyKeyboardMarkup(main_keyboard, resize_keyboard=True)
reply_cancel = ReplyKeyboardMarkup(cancel_keyboard, resize_keyboard=True, one_time_keyboard=True)

FILENAME = "habits.json"
user_habits = {}

def save_habits():
    with open(FILENAME, "w", encoding="utf-8") as f:
        json.dump(user_habits, f, ensure_ascii=False, indent=2)

def load_habits():
    global user_habits
    if os.path.exists(FILENAME):
        with open(FILENAME, "r", encoding="utf-8") as f:
            user_habits = json.load(f)
    else:
        user_habits = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Привет! Я бот для напоминаний о привычках.\nВыберите действие ниже:",
        reply_markup=reply_main,
    )

async def new_habit_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Введите новую привычку:",
        reply_markup=reply_cancel,
    )
    return ENTER_HABIT

async def enter_habit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    habit_text = update.message.text
    if habit_text.lower() == "отмена":
        await update.message.reply_text(
            "Создание привычки отменено.",
            reply_markup=reply_main,
        )
        return ConversationHandler.END

    context.user_data["new_habit"] = habit_text
    await update.message.reply_text(
        "Введите время напоминания в формате ЧЧ:ММ (например, 15:30):",
        reply_markup=reply_cancel,
    )
    return ENTER_TIME

async def enter_time(update: Update, context: ContextTypes.DEFAULT_TYPE):
    time_text = update.message.text
    if time_text.lower() == "отмена":
        await update.message.reply_text(
            "Создание привычки отменено.",
            reply_markup=reply_main,
        )
        return ConversationHandler.END

    try:
        hour, minute = map(int, time_text.split(":"))
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise ValueError
    except ValueError:
        await update.message.reply_text(
            "Неверный формат времени. Пожалуйста, введите снова в формате ЧЧ:ММ.",
            reply_markup=reply_cancel,
        )
        return ENTER_TIME

    habit = context.user_data.get("new_habit")
    user_id = str(update.message.from_user.id)

    if user_id not in user_habits:
        user_habits[user_id] = []
    user_habits[user_id].append({"habit": habit, "hour": hour, "minute": minute})

    save_habits()

    context.job_queue.run_daily(
        callback=send_habit_reminder,
        time=time(hour, minute),
        days=(0, 1, 2, 3, 4, 5, 6),
        data={"chat_id": update.effective_chat.id, "habit": habit},
        name=f"{user_id}_{habit}_{hour}_{minute}"
    )

    await update.message.reply_text(
        f"Привычка '{habit}' добавлена с напоминанием в {hour:02d}:{minute:02d}.",
        reply_markup=reply_main,
    )
    return ConversationHandler.END

async def send_habit_reminder(context: CallbackContext):
    job = context.job
    chat_id = job.data["chat_id"]
    habit = job.data["habit"]
    await context.bot.send_message(chat_id=chat_id, text=f"Напоминание: {habit}")

async def list_habits(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.message.from_user.id)
    habits = user_habits.get(user_id)
    if not habits:
        await update.message.reply_text("У вас еще нет сохраненных привычек.", reply_markup=reply_main)
        return

    message = "Ваши привычки и время напоминаний:\n\n"
    for i, h in enumerate(habits, 1):
        message += f"{i}. {h['habit']} — {h['hour']:02d}:{h['minute']:02d}\n"

    await update.message.reply_text(message, reply_markup=reply_main)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Действие отменено.", reply_markup=reply_main
    )
    return ConversationHandler.END

async def main_menu_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if text == "Мои привычки":
        await list_habits(update, context)
    elif text == "Новая привычка":
        return await new_habit_start(update, context)
    else:
        await update.message.reply_text(
            "Пожалуйста, выберите кнопку из меню ниже.",
            reply_markup=reply_main,
        )

def schedule_all_jobs(app):
    for user_id, habits in user_habits.items():
        for h in habits:
            app.job_queue.run_daily(
                callback=send_habit_reminder,
                time=time(h["hour"], h["minute"]),
                days=(0, 1, 2, 3, 4, 5, 6),
                data={"chat_id": int(user_id), "habit": h["habit"]},
                name=f"{user_id}_{h['habit']}_{h['hour']}_{h['minute']}"
            )

def main():
    TOKEN = "8083701310:AAGAEivD2wL8Ti0v-fikWsglkc-igjqY0nI"

    load_habits()

    app = ApplicationBuilder().token(TOKEN).build()

    schedule_all_jobs(app)

    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("^(Новая привычка)$"), new_habit_start)],
        states={
            ENTER_HABIT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, enter_habit),
                MessageHandler(filters.Regex("^(Отмена)$"), cancel),
            ],
            ENTER_TIME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, enter_time),
                MessageHandler(filters.Regex("^(Отмена)$"), cancel),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", cancel),
            MessageHandler(filters.Regex("^(Отмена)$"), cancel),
        ],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv_handler)
    app.add_handler(MessageHandler(filters.Regex("^(Мои привычки|Новая привычка)$"), main_menu_handler))

    app.run_polling()

if __name__ == "__main__":
    main()
