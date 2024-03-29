# verisure2mqtt

Simple verisure client to read Yale Doorman lock states and forward values to MQTT broker.

## Environament variables

See commonn environment variables from [MQTT-Framework](https://github.com/paulianttila/MQTT-Framework).

| **Variable**                   | **Default**            | **Descrition**                                                                                    |
|--------------------------------|------------------------|---------------------------------------------------------------------------------------------------|
| CFG_APP_NAME                   | verisure2mqtt          | Name of the app.                                                                                  |
| CFG_VERISURE_USERNAME          |                        | Username for Verisure login. At least read access required.                                       |
| CFG_VERISURE_PASSWORD          |                        | Password for Verisure login.                                                                      |
| CFG_VERISURE_TOKEN_FILE        | /data/.verisure-cookie | Token file for Verisure login. See [Create Verisure token](#create-verisure-token).               |
| CFG_VERISURE_INSTALLATION      |                        | Verisure installation name to use. If only one installation exits, it will be used automatically. |
| CFG_VERISURE_RATE_LIMIT        | 1                      | Number of requests allowed within period to Verisure site.                                        |
| CFG_VERISURE_RATE_LIMIT_PERIOD | 300                    | Time period for rate limit in seconds.                                                            |

## Example docker-compose.yaml

```yaml
version: "3.5"

services:
  verisure2mqtt:
    container_name: verisure2mqtt
    image: paulianttila/verisure2mqtt:2.0.0
    restart: unless-stopped
    environment:
      - CFG_LOG_LEVEL=DEBUG
      - CFG_MQTT_BROKER_URL=127.0.0.1
      - CFG_MQTT_BROKER_PORT=1883
      - CFG_VERISURE_USERNAME=<username>
      - CFG_VERISURE_PASSWORD=<password>
      - CFG_VERISURE_TOKEN_FILE=/app/.verisure-cookie
    volumes:
      - ./.verisure-cookie:/data/.verisure-cookie
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/healthy"]
      interval: 60s
      timeout: 3s
      start_period: 5s
      retries: 3
 ```


 # Multifactor authentication handling

 If multifactor authentication is enabled to Verisure account, then special steps need to done to make autheication succesfull.

 ## Manually

Cretae empty file.

```bash
touch .verisure-cookie
```

Run shell
```bash
docker-compose run verisure2mqtt sh
```

Create token (give code received by the text message from Verisure)
```bash
vsure $CFG_VERISURE_USERNAME $CFG_VERISURE_PASSWORD --cookie $CFG_VERISURE_TOKEN_FILE --mfa
```

## From MQTT

1. Send `true` to `verisure2mqtt/requestMFA` topic.
2. `verisure2mqtt/loginStatus` topic tell if request was succesfull.
3. Send code received by the text message from Verisure to `verisure2mqtt/validateMFA` topic.
4. `verisure2mqtt/loginStatus` topic tell if MFA validation was succesfull.