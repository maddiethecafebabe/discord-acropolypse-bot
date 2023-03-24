import discord
from discord.ext import commands
from .det import test_picture_bytes
import logging
import aiohttp
import io
import asyncio
import random

from typing import Tuple, List

def might_be_pixel_screenshot(url: str) -> bool:
    if url is None:
        return False

    try:
        fname = url.split("/")[-1].casefold()
    except IndexError:
        return False

    try:
        fext = fname.split(".")[-1].casefold()
    except IndexError:
        fext = "png".casefold()

    names = ["pxl_", "img_", "screenshot_"]
    names = names + [f"spoiler_{x}" for x in names]
    extensions = ["png", "jpg", "jpeg"]

    return any(x.casefold() in fname for x in names) and any(ext.casefold() == fext for ext in extensions)

def test_image(buf) -> bool:
    try:
        return test_picture_bytes(buf)
    except Exception as e:
        logging.warning(e)

async def check_image_from_url(url) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as res:
            if res.status == 429:
                delay = random.randint(5, 60)
                logging.warning(f"Hit 429, sleeping for {delay}")
                await asyncio.sleep(delay)
                return await check_image_from_url(url)
            elif res.status == 200:
                return test_image(await res.read())
            else:
                return False

async def check_message(message, dry_run: bool = False) -> Tuple[int, int, str]:
    for embed in message.embeds:
        try:
            url = embed.url
            if might_be_pixel_screenshot(url) and await check_image_from_url(url):
                try:
                    logging.info(f"Removing message...")
                    if not dry_run:
                        await message.delete()
                        return (1, 1, message.jump_url)
                    else:
                        return (1, 0, message.jump_url)
                except Exception as e:
                    logging.error(e)
                    return (1, 0, message.jump_url)
        except:
            pass

    vulnerable_attachments = []
    for attachment in message.attachments:
        # use .read() here because it deals with ratelimits better than pure aiohttp
        if might_be_pixel_screenshot(attachment.url) and test_image(await attachment.read()):
            logging.info(f"vuln image attachment: {attachment.url}")
            vulnerable_attachments.append(attachment)

    if vulnerable_attachments and not dry_run:
        logging.info(f"Removing attachments: {vulnerable_attachments}")
        try:
            await message.remove_attachments(*vulnerable_attachments)
            return (1, 1, message.jump_url)
        except Exception as e:
            logging.error(e)
            return (1, 0, message.jump_url)

    return (1 if vulnerable_attachments else 0, 0, message.jump_url)

async def check_channel(channel, dry_run: bool) -> Tuple[int, int, List[str]]:
    logging.info(f"checking channel #{channel.name}...")
    found, deleted, unpurged = 0, 0, []
    async for m in channel.history():
        (nfound, ndeleted, message) = await check_message(m, dry_run)
        found += nfound
        deleted += ndeleted
        if nfound != ndeleted:
            unpurged.append(message)
    return (found, deleted, unpurged)

async def check_server(guild, dry_run: bool) -> Tuple[int, int]:
    found, deleted, unpurged_guild = 0, 0, []
    for channel in guild.text_channels:
        (nfound, ndeleted, unpurged) = await check_channel(channel, dry_run)
        found += nfound
        deleted += ndeleted
        unpurged_guild += unpurged
    return (found, deleted, unpurged_guild)

async def send_report(ctx, found, deleted, unpurged):
    if found != deleted:
        fp = io.StringIO("\n".join(s for s in unpurged))
        file = discord.File(fp=fp, filename="message-urls.txt")
        await ctx.send(content=f"Found {found} images and deleted {deleted}. A list of undeleted messages is attached:", file=file)
    else:
        await ctx.send(f"Found and deleted {found} vulnerable images")
    logging.info("done.")

class Acropolypse(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @commands.is_owner()
    async def check_channel(self, ctx, dry_run: bool = False):
        res = await check_channel(ctx.channel, dry_run)
        await send_report(ctx, *res)

    @commands.command()
    @commands.is_owner()
    async def check_whole_server(self, ctx, dry_run: bool = False):
        res = await check_server(ctx.guild, dry_run)
        await send_report(ctx, *res)

async def setup(bot):
    await bot.add_cog(Acropolypse(bot))
