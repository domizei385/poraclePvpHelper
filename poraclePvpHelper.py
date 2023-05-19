import asyncio
import configparser
import os
import pickle
import sys
import time
from threading import Thread
from typing import Dict, Set

import mapadroid.plugins.pluginBase
from plugins.poraclePvpHelper.endpoints import register_custom_plugin_endpoints
import requests
from aiohttp import web
from mapadroid.db.DbWebhookReader import DbWebhookReader
from mapadroid.utils.RestHelper import RestApiResult, RestHelper
from mapadroid.utils.json_encoder import mad_json_dumps
from mapadroid.utils.madGlobals import MonSeenTypes

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "PogoPvpData"))
from pogopvpdata import PokemonData  # noqa: E402


class poraclePvpHelper(mapadroid.plugins.pluginBase.Plugin):
    """poraclePvpHelper plugin
    """

    def _file_path(self) -> str:
        return os.path.dirname(os.path.abspath(__file__))

    def __init__(self, subapp_to_register_to: web.Application, mad_parts: Dict):
        super().__init__(subapp_to_register_to, mad_parts)

        self._rootdir = os.path.dirname(os.path.abspath(__file__))
        self._mad = self._mad_parts
        self.logger = self._mad['logger']
        self.__db_wrapper = self._mad["db_wrapper"]
        self.__webhook_worker = self._mad["webhook_worker"]

        statusname = self._mad["args"].status_name
        self.logger.info("Got statusname: {}", statusname)
        if os.path.isfile(self._rootdir + "/plugin-" + statusname + ".ini"):
            self._pluginconfig.read(self._rootdir + "/plugin-" + statusname + ".ini")
            self.logger.info("loading instance-specific config for {}", statusname)
        else:
            self._pluginconfig.read(self._rootdir + "/plugin.ini")
            self.logger.info("loading standard plugin.ini")

        self._versionconfig.read(self._rootdir + "/version.mpl")
        self.author = self._versionconfig.get("plugin", "author", fallback="unknown")
        self.url = self._versionconfig.get("plugin", "url", fallback="https://www.maddev.eu")
        self.description = self._versionconfig.get("plugin", "description", fallback="unknown")
        self.version = self._versionconfig.get("plugin", "version", fallback="unknown")
        self.pluginname = self._versionconfig.get("plugin", "pluginname", fallback="https://www.maddev.eu")
        self.staticpath = self._rootdir + "/static/"
        self.templatepath = self._rootdir + "/template/"

        # plugin specific
        if not statusname in self._pluginconfig:
            self.logger.info("Using generic settings on instance with status-name {}", statusname)
            statusname = "settings"

        self.target = self._pluginconfig.get(statusname, "target", fallback=None)
        self.__worker_interval_sec = self._pluginconfig.getint(statusname, "interval", fallback=30)
        self.ranklength = self._pluginconfig.getint(statusname, "ranklength", fallback=100)
        self.maxlevel = self._pluginconfig.getint(statusname, "maxlevel", fallback=50)
        self.precalc = self._pluginconfig.getboolean(statusname, "precalc", fallback=False)
        self.saveData = self._pluginconfig.getboolean(statusname, "savedata", fallback=True)
        self.encid_string = self._pluginconfig.getboolean(statusname, "encidstring", fallback=True)

        self.__last_check = int(time.time())
        self.__webhook_receivers = []
        self.__pokemon_types: Set[MonSeenTypes] = set()
        self.__valid_mon_types: Set[MonSeenTypes] = {
            MonSeenTypes.encounter, MonSeenTypes.wild, MonSeenTypes.lure_encounter
        }

        # linking pages
        self._hotlink = [
            ("poraclePvpHelper Manual", "poraclepvphelper_manual", "poraclePvpHelper Manual"),
        ]

        if self._pluginconfig.getboolean("plugin", "active", fallback=False):
            register_custom_plugin_endpoints(self._plugin_subapp)

            for name, link, description in self._hotlink:
                self._mad_parts['madmin'].add_plugin_hotlink(name, link.replace("/", ""),
                                                             self.pluginname, self.description, self.author, self.url,
                                                             description, self.version)

    async def _perform_operation(self):
        if not self._pluginconfig.getboolean("plugin", "active", fallback=False):
            return False
        if not self._mad["args"].webhook:
            self.logger.error("Webhook worker is required but not enabled. Please set 'webhook' in your config "
                              "and restart. Stopping the plugin.")
            return False

        # load your stuff now
        self.logger.success("poraclePvpHelper Plugin starting operations ...")
        self.__build_webhook_receivers()
        loop = asyncio.get_running_loop()
        self._thread_poraclePvpHelper = loop.create_task(self.poraclePvpHelper())

        updateChecker = Thread(name="poraclePvpHelperUpdates", target=self.update_checker, )
        updateChecker.daemon = True
        updateChecker.start()

        return True

    def _pickle_data(self, data):
        if self.saveData:
            try:
                with open("{}/.data.pickle".format(os.path.dirname(os.path.abspath(__file__))), "wb") as datafile:
                    pickle.dump(data, datafile, -1)
                    self.logger.success("Saved data to pickle file")
                    return True
            except Exception as e:
                self.logger.warning("Failed saving to pickle file: {}".format(e))
                return False
        else:
            return False

    def _is_update_available(self):
        update_available = None
        try:
            r = requests.get("https://raw.githubusercontent.com/crhbetz/mp-poraclePvpHelper/master/version.mpl")
            self.github_mpl = configparser.ConfigParser()
            self.github_mpl.read_string(r.text)
            self.available_version = self.github_mpl.get("plugin", "version", fallback=self.version)
        except Exception:
            return None

        try:
            from pkg_resources import parse_version
            update_available = parse_version(self.version) < parse_version(self.available_version)
        except Exception:
            pass

        if update_available is None:
            try:
                from distutils.version import LooseVersion
                update_available = LooseVersion(self.version) < LooseVersion(self.available_version)
            except Exception:
                pass

        if update_available is None:
            try:
                from packaging import version
                update_available = version.parse(self.version) < version.parse(self.available_version)
            except Exception:
                pass

        return update_available

    def update_checker(self):
        while True:
            self.logger.debug("poraclePvpHelper checking for updates ...")
            result = self._is_update_available()
            if result:
                self.logger.warning("An update of poraclePvpHelper from version {} to version {} is available!",
                                    self.version, self.available_version)
            elif result is False:
                self.logger.success("poraclePvpHelper is up-to-date! ({} = {})", self.version, self.available_version)
            else:
                self.logger.warning("Failed checking for updates!")
            time.sleep(3600)

    # copied from mapadroid/webhook/webhookworker.py
    def __build_webhook_receivers(self):
        webhooks = self.target.replace(" ", "").split(",")

        for webhook in webhooks:
            sub_types = None
            url = webhook.strip()

            if url.startswith("["):
                end_pos = url.index("]")
                raw_sub_types = url[1:end_pos].strip()
                url = url[end_pos + 1:]
                sub_types = raw_sub_types.split(" ")
                sub_types = [t.replace(" ", "") for t in sub_types]

                if "pokemon" in sub_types:
                    sub_types.append("encounter")

                for vmtype in self.__valid_mon_types:
                    if vmtype.name in sub_types:
                        self.__pokemon_types.add(vmtype)
            else:
                for valid_mon_type in self.__valid_mon_types:
                    self.__pokemon_types.add(valid_mon_type)

            self.__webhook_receivers.append({
                "url": url.replace(" ", ""),
                "types": sub_types
            })

    # copied from mapadroid/webhook/webhookworker.py
    @staticmethod
    def _payload_chunk(payload, size):
        if size == 0:
            return [payload]

        return [payload[x: x + size] for x in range(0, len(payload), size)]

    # copied from mapadroid/webhook/webhookworker.py
    @staticmethod
    def __payload_type_count(payload):
        count = {}

        for elem in payload:
            count[elem["type"]] = count.get(elem["type"], 0) + 1

        return count

    # copied from mapadroid/webhook/webhookworker.py + some variables adjusted
    async def __send_webhook(self, payloads):
        if len(payloads) == 0:
            self.logger.debug2("Payload empty. Skip sending to webhook.")
            return

        current_wh_num = 1
        for webhook in self.__webhook_receivers:
            payload_to_send = []
            sub_types = webhook.get('types')

            if sub_types is not None:
                for payload in payloads:
                    if payload["type"] in sub_types or \
                        (payload["message"].get("seen_type", None) in sub_types):
                        payload_to_send.append(payload)
            else:
                payload_to_send = payloads

            if len(payload_to_send) == 0:
                self.logger.debug2("Payload empty. Skip sending to: {} (Filter: {})", webhook.get('url'), sub_types)
                continue
            else:
                self.logger.debug2("Sending to webhook: {} (Filter: {})", webhook.get('url'), sub_types)

            payload_list = self.__payload_chunk(payload_to_send, 100)

            current_pl_num = 1
            for payload_chunk in payload_list:
                self.logger.debug4("Python data for payload: {}", payload_chunk)
                self.logger.debug4("Payload: {}", await mad_json_dumps(payload_chunk))

                try:
                    response: RestApiResult = await RestHelper.send_post(webhook.get('url'),
                                                                         data=payload_chunk,
                                                                         headers={"Content-Type": "application/json"},
                                                                         params=None,
                                                                         timeout=5)
                    if response.status_code != 200:
                        self.logger.warning("Webhook destination {} returned status code other than 200 OK: {}",
                                       webhook.get('url'), response.status_code)
                    else:
                        if len(self.__webhook_receivers) > 1:
                            whcount_text = " [wh {}/{}]".format(current_wh_num, len(self.__webhook_receivers))
                        else:
                            whcount_text = ""

                        if len(payload_list) > 1:
                            whchunk_text = " [pl {}/{}]".format(current_pl_num, len(payload_list))
                        else:
                            whchunk_text = ""

                        self.logger.success("Successfully sent payload to webhook{}{}. Stats: {}", whchunk_text,
                                       whcount_text, await mad_json_dumps(self.__payload_type_count(payload_chunk)))
                except Exception as e:
                    self.logger.warning("Exception occurred while sending webhook: {}", e)

                current_pl_num += 1
            current_wh_num += 1

    async def __create_payload(self, data: PokemonData):
        self.logger.debug("Fetching data changed since {}", self.__last_check)

        payload = []
        async with self.__db_wrapper as session, session:
            try:
                if self.__pokemon_types:
                    mons_from_db = await DbWebhookReader.get_mon_changed_since(session, self.__last_check, self.__pokemon_types)
                    payload = self.__webhook_worker._WebhookWorker__prepare_mon_data(mons_from_db)
                    for mon in payload:
                        if "individual_attack" in mon["message"]:
                            content = mon["message"]
                            if self.encid_string:
                                content["encounter_id"] = str(content["encounter_id"])
                            try:
                                form = content["form"]
                            except Exception:
                                form = 0
                            try:
                                great, ultra = data.getPoraclePvpInfo(content["pokemon_id"], form,
                                                                      content["individual_attack"],
                                                                      content["individual_defense"],
                                                                      content["individual_stamina"],
                                                                      content["pokemon_level"],
                                                                      content["gender"])
                            except Exception as e:
                                self.logger.warning("Failed processing mon #{}-{}. Skipping. Error: {}",
                                                    content["pokemon_id"], form, e)
                                continue
                            if len(great) > 0:
                                mon["message"]["pvp_rankings_great_league"] = great
                            if len(ultra) > 0:
                                mon["message"]["pvp_rankings_ultra_league"] = ultra
            except Exception:
                self.logger.opt(exception=True).error("Unhandled exception in poraclePvpHelper! Trying to continue... ")

        self.logger.debug("Done fetching data + building payload")

        return payload

    async def poraclePvpHelper(self):
        self.__last_check = int(time.time())
        if not self.target:
            self.logger.error("no webhook (target) defined in settings - what am I doing here? ;)")
            return

        if os.path.isfile("{}/data.pickle".format(self._rootdir)):
            os.rename("{}/data.pickle".format(self._rootdir), "{}/.data.pickle".format(self._rootdir))
            self.logger.success("migrated data.pickle to .data.pickle (hidden file)")

        try:
            with open("{}/.data.pickle".format(self._rootdir), "rb") as datafile:
                data = pickle.load(datafile)
        except Exception as e:
            self.logger.debug("exception trying to load pickle'd data: {}".format(e))
            add_string = " - start initialization" if self.precalc else " - will calculate as needed"
            self.logger.warning(f"Failed loading previously calculated data{add_string}")
            data = None

        if not data:
            data = PokemonData(self.ranklength, self.maxlevel, precalc=self.precalc)
            self._pickle_data(data)

        if not data:
            self.logger.error("Failed acquiring PokemonData object! Stopping the plugin.")
            return

        self.logger.success("PokemonData object acquired")

        w = 0
        while not self.__webhook_worker and w < 12:
            w += 1
            self.logger.warning("waiting for the webhook worker to be initialized ...")
            await asyncio.sleep(10)
        if w > 11:
            self.logger.error("Failed trying to access the webhook worker with webhook enabled. Please contact "
                              "the developer.")
            return

        while True:
            # Always check modifications of intervals N - 6 to NOW given processing of queues may take some time...
            preparing_timestamp = int(time.time()) - 6 * self.__worker_interval_sec

            # fetch data and create payload
            full_payload = await self.__create_payload(data)

            # send our payload
            await self.__send_webhook(full_payload)

            self.__last_check = preparing_timestamp

            if self.saveData and data.is_changed():
                self._pickle_data(data)
                data.saved()

            await asyncio.sleep(self.__worker_interval_sec)
