a bot to scan a channel or whole server for image attachments or urls that might be pixel screenshots, downloads them and checks them for CVE-2023-21036. if it thinks they are it tries to delete the attachment/message. at last it will give out a small statistic with links to messages that it thinks are affected but couldnt delete (e.g. due to permissions)

for detection this uses a script by retr0id <https://gist.github.com/DavidBuchanan314/93de9d07f7fab494bcdf17c2bd6cef02> with slight adaptations by <https://github.com/infobyte/CVE-2023-21036>

the code is mostly horrible and will probably do horrible things if you run it on a large server because the ""ratelimiting"" is very bad. im not responsible if you get your account/bot thrown into the shadowrealm

this needs the `message_content` intent and a `DISCORD_TOKEN` environment variable

# License

im not sure about the license on the det.py script but `cog/acropolypse.py` and `bot.py` are released into the public domain so feel free to use them in your own bot or tweak them to your needs
