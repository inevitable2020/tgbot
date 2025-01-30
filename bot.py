import os
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

# Load API keys from Railway environment variables
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # VirusTotal API Key
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")  # Telegram Bot Token

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
