import os
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext

# Load API keys from Railway environment variables
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")  # VirusTotal API Key
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")  # Telegram Bot Token

async def start(update: Update, context: CallbackContext):
    await update.message.reply_text("Send me a file or link to scan.")

async def scan_url(update: Update, context: CallbackContext):
    url = update.message.text
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    await update.message.reply_text(str(response.json()))

async def scan_file(update: Update, context: CallbackContext):
    file = await update.message.document.get_file()
    file_path = await file.download_as_bytearray()

    headers = {"x-apikey": API_KEY}
    files = {"file": file_path}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    await update.message.reply_text(str(response.json()))

def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_url))
    app.add_handler(MessageHandler(filters.Document.ALL, scan_file))

    app.run_polling()

if __name__ == "__main__":
    main()
