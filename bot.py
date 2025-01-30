import os
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

# Load API keys from Railway environment
API_KEY = os.getenv("120b6f95344f65f89b96a963db43e83a03e3d6de05e19b8cf23ee8c1aa64e893")
BOT_TOKEN = os.getenv("7869390750:AAFikWKtt8EryptP9NUyRFDXvXbTd2sEM9g")

def start(update: Update, context: CallbackContext):
    update.message.reply_text("Send me a file or link to scan.")

def scan_url(update: Update, context: CallbackContext):
    url = update.message.text
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    update.message.reply_text(str(response.json()))

def scan_file(update: Update, context: CallbackContext):
    file = update.message.document.get_file()
    file_path = file.download()

    headers = {"x-apikey": API_KEY}
    files = {"file": open(file_path, "rb")}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    update.message.reply_text(str(response.json()))

def main():
    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, scan_url))
    dp.add_handler(MessageHandler(Filters.document, scan_file))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
