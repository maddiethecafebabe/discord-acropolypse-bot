import discord
from discord.ext import commands
import os
import dotenv
import logging

discord.utils.setup_logging()

dotenv.load_dotenv()

intents = discord.Intents.default()
intents.message_content = True

class AcropolypseBot(commands.Bot):
    async def on_ready(self):
        logging.info(f'Logged in as {self.user}')

        await self.load_extension("cog.acropolypse")

bot = AcropolypseBot(intents=intents, command_prefix="!!")
bot.run(os.environ.get("DISCORD_TOKEN"))
