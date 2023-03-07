from mqtt_framework import Framework
from mqtt_framework import Config
from mqtt_framework.callbacks import Callbacks
from mqtt_framework.app import TriggerSource

from prometheus_client import Counter

from datetime import datetime
import verisure
from ratelimit import limits


class MyConfig(Config):
    def __init__(self):
        super().__init__(self.APP_NAME)

    APP_NAME = "verisure2mqtt"

    # App specific variables

    VERISURE_USERNAME = None
    VERISURE_PASSWORD = None
    VERISURE_TOKEN_FILE = "~/.verisure-cookie"


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
        self.session = verisure.Session(
            self.config["VERISURE_USERNAME"],
            self.config["VERISURE_PASSWORD"],
            self.config["VERISURE_TOKEN_FILE"],
        )
        self.login_done = False

    def get_version(self) -> str:
        return "1.0.0"

    def stop(self) -> None:
        self.logger.debug("Exit")

    def subscribe_to_mqtt_topics(self) -> None:
        pass

    def mqtt_message_received(self, topic: str, message: str) -> None:
        pass

    def do_healthy_check(self) -> bool:
        return True

    # Do work
    def do_update(self, trigger_source: TriggerSource) -> None:
        self.logger.debug(f"Update called, trigger_source={trigger_source}")
        self.update()

    @limits(calls=2, period=900)
    def update(self) -> None:
        self.logger.debug("Fetch data from verisure")
        self.login()

        self.succesfull_fecth_metric.inc()
        try:
            self.update_data_to_mqtt()
        except Exception as e:
            self.fecth_errors_metric.inc()
            self.logger.error(f"Error occured: {e}")
            self.logger.debug(f"Error occured: {e}", exc_info=True)
            self.logger.info("Retry with relogin")
            self.login(relogin=True)
            self.update_data_to_mqtt()

    def login(self, relogin=False) -> None:
        if not self.login_done or relogin:
            self.logger.debug("Login")
            self.login_metric.inc()
            try:
                self.session.login()
            except Exception:
                self.login_errors_metric.inc()
                raise
            self.login_done = True
            self.logger.debug(f"Installations: {self.session.installations}")

    def update_data_to_mqtt(self) -> None:
        overview = self.fecth_overview_from_verisure()
        for lock in overview["doorLockStatusList"]:
            area = lock["area"]
            self.publish_value_to_mqtt_topic(
                f"{area}/currentLockState", lock["currentLockState"], True
            )
            self.publish_value_to_mqtt_topic(
                f"{area}/currentLockState", lock["lockedState"], True
            )
            self.publish_value_to_mqtt_topic(
                f"{area}/currentLockState", lock["deviceLabel"], True
            )
            self.publish_value_to_mqtt_topic(
                f"{area}/currentLockState", lock["eventTime"], True
            )
        self.publish_value_to_mqtt_topic(
            "lastUpdateTime",
            str(datetime.now().replace(microsecond=0).isoformat()),
            True,
        )

    def fecth_overview_from_verisure(self):
        self.logger.debug("Fetch information from verisure")
        overview = self.session.get_overview()
        self.logger.debug(f"Received data: {overview}")
        return overview


if __name__ == "__main__":
    Framework().start(MyApp(), MyConfig(), blocked=True)
