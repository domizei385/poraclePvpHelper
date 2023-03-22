from aiohttp import web

from plugins.poraclePvpHelper.endpoints.poraclePvpHelperManualEndpoint import poraclePvpHelperManualEndpoint


def register_custom_plugin_endpoints(app: web.Application):
    # Simply register any endpoints here. If you do not intend to add any views (which is discouraged) simply "pass"
    app.router.add_view('/poraclePvpHelper_manual', poraclePvpHelperManualEndpoint, name='poraclePvpHelper_manual')
