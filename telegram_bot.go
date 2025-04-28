package main

import (
	"fmt"
	"log"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

const adminChatID = "1515643757" // Replace with the actual admin chat ID

func startTelegramBot() {
	botToken := os.Getenv("BOT_TOKEN")
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}
	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates, err := bot.GetUpdatesChan(u)
	if err != nil {
		log.Panic(err)
	}

	// Listen for incoming updates
	for update := range updates {
		if update.Message != nil && update.Message.IsCommand() {
			chatID := update.Message.Chat.ID
			switch update.Message.Command() {
			case "start":
				sendBotMenu(bot, chatID)
			case "admin":
				// Hard-coded admin ChatID check
				if fmt.Sprintf("%d", chatID) == adminChatID {
					sendAdminMenu(bot, chatID)
				} else {
					msg := tgbotapi.NewMessage(chatID, "Access denied. Only admin can use this command.")
					bot.Send(msg)
				}
			default:
				msg := tgbotapi.NewMessage(chatID, "Unknown command.")
				bot.Send(msg)
			}
		} else if update.CallbackQuery != nil {
			chatID := update.CallbackQuery.Message.Chat.ID
			data := update.CallbackQuery.Data
			switch data {
			case "create_link":
				url := fmt.Sprintf("http://realadlabs.in/bot/create-link?chat_id=%d", update.CallbackQuery.Message.Chat.ID)
				response := "Click here to create a link: " + url
				msg := tgbotapi.NewMessage(chatID, response)
				bot.Send(msg)
			case "manage_link":
				url := fmt.Sprintf("http://realadlabs.in/bot/manage-link?chat_id=%d", update.CallbackQuery.Message.Chat.ID)
				response := "Click here to manage your links: " + url
				msg := tgbotapi.NewMessage(chatID, response)
				bot.Send(msg)
			case "link_stats":
				url := fmt.Sprintf("http://realadlabs.in/bot/link-stats?chat_id=%d", update.CallbackQuery.Message.Chat.ID)
				response := "Click here to view your link stats: " + url
				msg := tgbotapi.NewMessage(chatID, response)
				bot.Send(msg)
			default:
				msg := tgbotapi.NewMessage(chatID, "Unknown action.")
				bot.Send(msg)
			}
			// Acknowledge the callback to remove the loading state in the Telegram client.
			callback := tgbotapi.NewCallback(update.CallbackQuery.ID, "")
			bot.AnswerCallbackQuery(callback)
		}
	}
}

// sendBotMenu builds and sends the inline keyboard for normal users.
func sendBotMenu(bot *tgbotapi.BotAPI, chatID int64) {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Create Link", "create_link"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Manage Link", "manage_link"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Link Stats", "link_stats"),
		),
	)
	msg := tgbotapi.NewMessage(chatID, "Welcome to realadlabs.in Telegram Bot!\nSelect an option:")
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}

// sendAdminMenu builds and sends the admin menu.
func sendAdminMenu(bot *tgbotapi.BotAPI, chatID int64) {
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonURL("Admin Panel", "http://realadlabs.in/admin"),
		),
	)
	msg := tgbotapi.NewMessage(chatID, "Welcome Admin!\nAccess your admin panel below:")
	msg.ReplyMarkup = keyboard
	bot.Send(msg)
}
