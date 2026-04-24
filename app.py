from aiohttp import web
from datetime import datetime, timezone

ads = {}
next_id = 1


async def create_ad(request: web.Request) -> web.Response:
    global next_id
    data = await request.json()
    if not all(k in data for k in ('title', 'description', 'owner')):
        return web.json_response(
            {'error': 'Missing required fields: title, description, owner'},
            status=400
        )
    ad = {
        'id': next_id,
        'title': data['title'],
        'description': data['description'],
        'created_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'owner': data['owner']
    }
    ads[next_id] = ad
    next_id += 1
    return web.json_response(ad, status=201)


async def get_ad(request: web.Request) -> web.Response:
    ad_id = int(request.match_info['id'])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({'error': 'Ad not found'}, status=404)
    return web.json_response(ad)


async def delete_ad(request: web.Request) -> web.Response:
    ad_id = int(request.match_info['id'])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({'error': 'Ad not found'}, status=404)
    del ads[ad_id]
    return web.Response(status=204)


async def update_ad(request: web.Request) -> web.Response:
    ad_id = int(request.match_info['id'])
    ad = ads.get(ad_id)
    if ad is None:
        return web.json_response({'error': 'Ad not found'}, status=404)
    data = await request.json()
    if not data:
        return web.json_response({'error': 'No data provided'}, status=400)
    if 'title' in data:
        ad['title'] = data['title']
    if 'description' in data:
        ad['description'] = data['description']
    if 'owner' in data:
        ad['owner'] = data['owner']
    return web.json_response(ad)


async def list_ads(request: web.Request) -> web.Response:
    return web.json_response(list(ads.values()))


app = web.Application()
app.router.add_post('/ads', create_ad)
app.router.add_get('/ads', list_ads)
app.router.add_get('/ads/{id:\d+}', get_ad)
app.router.add_delete('/ads/{id:\d+}', delete_ad)
app.router.add_put('/ads/{id:\d+}', update_ad)


if __name__ == '__main__':
    web.run_app(app, port=8080)
