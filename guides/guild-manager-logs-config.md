Config exists at `config/config.json` and is gitignored for safety, so here is the exact set of values the guild-manager logging now needs.

Create or edit `config/config.json` with at least these two keys:

```json
{
  "discord": {
    "logs_channel": "YOUR_LOGS_CHANNEL_ID",
    "censored_logs_channel": "YOUR_CENSORED_CHANNEL_ID"
  }
}
```

How to get the IDs:

1. Enable Developer Mode in Discord: User Settings → App Settings → Advanced → Developer Mode.
2. Right-click the logs channel in Discord → Copy Channel ID.
3. Right-click the censored channel (optional) → Copy Channel ID.

Then restart the bot and run `/guilds list`. Every invite the bot creates and every leave it performs will be `log.info` recorded in the console and, if the channel exists and is reachable, posted as a small embed to that channel via `shared/send_logs.send_logs`.

If `logs_channel` is empty, all guild-management logging is silently disabled. A wrong `logs_channel` is not fatal to the bot: it is detected once per process and reported as a warning.
