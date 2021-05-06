import google.auth
import google.auth.transport.requests
import google.oauth2.id_token
import google.oauth2._id_token_async
import google.auth.transport._aiohttp_requests
import asyncio
import aiohttp


def run_id_token_sync():
    req = google.auth.transport.requests.Request()
    token = google.oauth2.id_token.fetch_id_token(req, "https://pubsub.googleapis.com")
    print(token)


async def async_fetch_id_token():
    req = google.auth.transport._aiohttp_requests.Request()
    #req.session = aiohttp.ClientSession()

    token = await google.oauth2._id_token_async.fetch_id_token(req, "https://pubsub.googleapis.com")
    await req.session.close()
    print(token)


def run_id_token_async():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_fetch_id_token())
    loop.close()

run_id_token_sync()
run_id_token_async()