import json
from mqtt_framework import Framework
from mqtt_framework import Config
from mqtt_framework.callbacks import Callbacks
from mqtt_framework.app import TriggerSource

from prometheus_client import Counter

from datetime import datetime
import verisure
from verisure import (
    LoginError as VerisureLoginError,
    ResponseError as VerisureResponseError,
)
from pyrate_limiter import RequestRate, Limiter


class MfaRequired(Exception):
    """Verisure Multifactor Authetication is required"""


class MyConfig(Config):
    def __init__(self):
        super().__init__(self.APP_NAME)

    APP_NAME = "verisure2mqtt"

    # App specific variables

    VERISURE_USERNAME = None
    VERISURE_PASSWORD = None
    VERISURE_TOKEN_FILE = "/data/.verisure-cookie"  # nosec
    VERISURE_INSTALLATION = None
    VERISURE_RATE_LIMIT = 1
    VERISURE_RATE_LIMIT_PERIOD = 300


class MyApp:
    def init(self, callbacks: Callbacks) -> None:
        self.logger = callbacks.get_logger()
        self.config = callbacks.get_config()
        self.metrics_registry = callbacks.get_metrics_registry()
        self.add_url_rule = callbacks.add_url_rule
        self.publish_value_to_mqtt_topic = callbacks.publish_value_to_mqtt_topic
        self.subscribe_to_mqtt_topic = callbacks.subscribe_to_mqtt_topic
        self.succesfull_fecth_metric = Counter(
            "succesfull_fecth", "", registry=self.metrics_registry
        )
        self.fecth_errors_metric = Counter(
            "fecth_errors", "", registry=self.metrics_registry
        )
        self.login_metric = Counter("login_count", "", registry=self.metrics_registry)
        self.login_errors_metric = Counter(
            "login_errors_count", "", registry=self.metrics_registry
        )
        self.verisure = verisure.Session(
            self.config["VERISURE_USERNAME"],
            self.config["VERISURE_PASSWORD"],
            cookie_file_name=self.config["VERISURE_TOKEN_FILE"],
        )
        self.login_done = False
        self.mfa_needed = False
        self.mfa_ongoing = False
        self.mfa_validate_ongoing = False
        self.installations = None
        self.giid = None
        self.limiter = Limiter(
            RequestRate(
                self.config["VERISURE_RATE_LIMIT"],
                self.config["VERISURE_RATE_LIMIT_PERIOD"],
            )
        )

    def get_version(self) -> str:
        return "2.2.0"

    def stop(self) -> None:
        self.logger.debug("Exit")

    def subscribe_to_mqtt_topics(self) -> None:
        self.subscribe_to_mqtt_topic("requestMFA")
        self.subscribe_to_mqtt_topic("validateMFA")
        self.subscribe_to_mqtt_topic("sendCommand")

    def mqtt_message_received(self, topic: str, message: str) -> None:
        # sourcery skip: raise-specific-error
        self.logger.debug(f"MQTT message received: topic='{topic}' message='{message}'")

        try:
            if topic == "requestMFA" and message.lower() == "true":
                self.request_mfa()
            elif topic == "validateMFA" and message != "":
                self.validate_mfa(message)
            elif topic == "sendCommand" and message != "":
                self.handle_command(message)
            else:
                raise Exception(f"Unknown command '{topic}'")
        except Exception as e:
            err = (
                f"Error occured while processing message "
                f"'{message}' from topic '{topic}'",
            )
            self.handle_exception(err, e)

    def handle_exception(self, msg: str, e: Exception) -> None:
        self.logger.error(f"{msg}: {e}")
        self.logger.debug(f"Exception: {e}", exc_info=True)
        self.publish_value_to_mqtt_topic("lastError", msg)

    def do_healthy_check(self) -> bool:
        return True

    # Do work
    def do_update(self, trigger_source: TriggerSource) -> None:
        self.logger.debug(f"Update called, trigger_source={trigger_source}")
        self.update()

    def update(self):
        try:
            self.logger.debug("Fetch data from verisure")
            self.limiter.try_acquire("Verisure update")
            self.login()
            overview = self.fecth_data_from_verisure()
            self.logger.debug(f"Received overview: {overview}")
            self.update_data_to_mqtt(overview)
            self.succesfull_fecth_metric.inc()
        except Exception as e:
            self.logger.error(f"Error occured: {e}")
            self.logger.debug(f"Error occured: {e}", exc_info=True)

    def login(self) -> None:
        if self.mfa_needed:
            self.update_status("Multifactor authentication login needed")
            raise MfaRequired("Multifactor authentication login needed")

        if self.login_done:
            try:
                self.logger.debug("Update token")
                self.verisure.update_cookie()
                return
            except VerisureLoginError as e:
                self.handle_failed_login(e, "Token update failed")

        self.logger.debug("Login")
        self.login_metric.inc()

        try:
            self.installations = self.verisure.login()
            self.handle_succesfull_login()
            return
        except VerisureLoginError as e:
            self.login_errors_metric.inc()
            if "Multifactor authentication enabled" in str(e):
                try:
                    self.installations = self.verisure.login_cookie()
                    self.handle_succesfull_login()
                except VerisureLoginError as e:
                    if "Multifactor authentication enabled" in str(e):
                        self.handle_mfa_required_error(e)
                    else:
                        self.handle_failed_login(e)
                    raise
            else:
                self.handle_failed_login(e)
                raise
        except Exception as e:
            self.handle_failed_login(e)
            raise

    def handle_succesfull_login(self):
        self.login_done = True
        self.mfa_needed = False
        self.update_status("Login succcesfull done")
        if self.giid is None:
            self.handle_installation()

    def handle_failed_login(self, e: Exception = None, msg: str = None):
        self.login_errors_metric.inc()
        self.login_done = False
        if msg is None:
            self.logger.error(f"Login failed: {e}")
        else:
            self.logger.error(f"{msg}: {e}")
        self.update_status("Login failed")

    def handle_mfa_required_error(self, e: Exception = None):
        self.mfa_needed = True
        self.login_done = False
        self.logger.error(f"Multifactor authentication login needed: {e}")
        self.update_status("Multifactor authentication login needed")

    def handle_installation(self):
        self.logger.debug(f"Installations: {self.installations}")
        giids = self.get_installation_giids()
        installation = self.config["VERISURE_INSTALLATION"]

        if installation is None:
            if len(giids):
                installation = next(iter(giids))
                self.logger.debug(
                    f"Only one installation '{installation}' available, using it"
                )
                self.set_giid(installation, giids)
            else:
                self.logger.error(
                    "Multiple installations found, define which one should be used"
                    " by VERISURE_INSTALLATION parameter"
                )
        else:
            self.set_giid(installation, giids)

    def set_giid(self, giid_name: str, giids: dict) -> None:
        giid = giids[giid_name]
        self.logger.debug(f"Using installation '{giid_name}' giid '{giid}'")
        self.giid = giid
        self.verisure.set_giid(giid)

    def get_installation_giids(self) -> dict:
        giids = {
            inst["alias"]: inst["giid"]
            for inst in self.installations["data"]["account"]["installations"]
        }
        self.logger.debug(f"Giids found: {giids}")
        return giids

    def request_mfa(self) -> None:
        if self.mfa_ongoing is False:
            self.mfa_ongoing = True
            self.logger.info("Request MFA")
            try:
                self.verisure.request_mfa()
                self.update_status("Verification code needed")
            except VerisureLoginError as e:
                self.logger.error(f"Request MFA error: {e}")
                self.update_status("MFA request failed")
            finally:
                self.logger.info("Request MFA done")
                self.mfa_ongoing = False
        else:
            self.logger.info("Request MFA already ongoing")

    def validate_mfa(self, message: str) -> None:
        if self.mfa_validate_ongoing is False:
            self.mfa_validate_ongoing = True
            self.logger.info("Validate MFA")
            try:
                self.installations = self.verisure.validate_mfa(message)
                self.handle_succesfull_login()
            except VerisureResponseError as e:
                self.logger.error(f"MFA validate error: {e}")
                self.update_status("MFA validate failed")
            finally:
                self.logger.info("MFA validate done")
                self.mfa_validate_ongoing = False
        else:
            self.logger.info("Validate MFA already ongoing")

    def handle_command(self, message: str) -> None:
        data = json.loads(message)
        sn = data["deviceLabel"]
        command = data["command"]

        match command:
            case "enableAutolock":
                self.verisure.set_autolock_enabled(
                    device_label=sn, auto_lock_enabled=True, giid=self.giid
                )
            case "disableAutolock":
                self.verisure.set_autolock_enabled(
                    device_label=sn, auto_lock_enabled=False, giid=self.giid
                )

    def update_data_to_mqtt(self, overview: dict) -> None:
        self.publish_broadband(overview)
        self.publish_locks(overview)
        self.publish_value_to_mqtt_topic(
            "lastUpdateTime",
            str(datetime.now().replace(microsecond=0).isoformat()),
            True,
        )

    def publish_broadband(self, overview: dict) -> None:
        self.publish_value_to_mqtt_topic(
            "broadband/isBroadbandConnected",
            overview["broadband"]["isBroadbandConnected"],
            True,
        )

        self.publish_value_to_mqtt_topic(
            "broadband/testDate",
            self.convert_to_local_time(overview["broadband"]["testDate"]),
            True,
        )

    def convert_to_local_time(self, time: str) -> str:
        # sourcery skip: aware-datetime-for-utc
        local_time = datetime.fromisoformat(time) + (datetime.now() - datetime.utcnow())
        return str(local_time.replace(microsecond=0).replace(tzinfo=None).isoformat())

    def publish_locks(self, overview: dict) -> None:
        for lockname in overview["locks"]:
            lock = overview["locks"].get(lockname)
            area = lock["device"]["area"]
            self.publish_value_to_mqtt_topic(
                f"locks/{area}/lockState", lock["lockStatus"], True
            )
            self.publish_value_to_mqtt_topic(
                f"locks/{area}/doorState", lock["doorState"], True
            )
            self.publish_value_to_mqtt_topic(
                f"locks/{area}/deviceLabel", lock["device"]["deviceLabel"], True
            )
            self.publish_value_to_mqtt_topic(
                f"locks/{area}/eventTime",
                self.convert_to_local_time(lock["eventTime"]),
                True,
            )
            self.publish_value_to_mqtt_topic(
                f"locks/{area}/lockMethod", lock["lockMethod"], True
            )

    def fecth_data_from_verisure(self) -> dict:
        def unpack(overview: list, value: str) -> dict | list:
            unpacked = [
                item["data"]["installation"][value]
                for item in overview
                if value in item.get("data", {}).get("installation", {})
            ]
            return unpacked[0]

        self.logger.debug("Fetch information from verisure")
        overview = self.verisure.request(
            self.verisure.arm_state(),
            self.verisure.broadband(),
            self.verisure.cameras(),
            self.verisure.climate(),
            self.verisure.door_window(),
            self.verisure.smart_lock(),
            self.verisure.smartplugs(),
            self.verisure.door_lock_configuration(),
        )
        self.logger.debug(f"Received data: {overview}")
        return {
            "alarm": unpack(overview, "armState"),
            "broadband": unpack(overview, "broadband"),
            "cameras": {
                device["device"]["deviceLabel"]: device
                for device in unpack(overview, "cameras")
            },
            "climate": {
                device["device"]["deviceLabel"]: device
                for device in unpack(overview, "climates")
            },
            "door_window": {
                device["device"]["deviceLabel"]: device
                for device in unpack(overview, "doorWindows")
            },
            "locks": {
                device["device"]["deviceLabel"]: device
                for device in unpack(overview, "smartLocks")
            },
            "smart_plugs": {
                device["device"]["deviceLabel"]: device
                for device in unpack(overview, "smartplugs")
            },
        }

    def update_status(self, status: str) -> None:
        self.publish_value_to_mqtt_topic(
            "loginStatus",
            status,
            True,
        )


if __name__ == "__main__":
    Framework().run(MyApp(), MyConfig())
