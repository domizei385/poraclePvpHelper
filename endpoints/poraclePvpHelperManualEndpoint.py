from mapadroid.plugins.endpoints.AbstractPluginEndpoint import AbstractPluginEndpoint
import aiohttp_jinja2


class poraclePvpHelperManualEndpoint(AbstractPluginEndpoint):
    """
    "/poraclepvphelper_manual"
    """

    # TODO: Auth
    @aiohttp_jinja2.template('poraclePvpHelper_manual.html')
    async def get(self):
        return {"header": "poraclePvpHelper Manual",
                "title": "poraclePvpHelper Manual"}
