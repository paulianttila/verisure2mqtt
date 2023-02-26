# verisure2mqtt

Simple verisure client to read Yale Doorman lock states and forward values to MQTT broker.

## Environament variables

See commonn environment variables from [MQTT-Framework](https://github.com/paulianttila/MQTT-Framework).

| **Variable**               | **Default**   | **Descrition**                                                                      |
|----------------------------|---------------|-------------------------------------------------------------------------------------|
| CFG_APP_NAME               | verisure2mqtt | Name of the app.                                                                    |
| CFG_VERISURE_USERNAME      |               | Username for Verisure login. At least read access required.                         |
| CFG_VERISURE_PASSWORD      |               | Password for Verisure login.                                                        |
| CFG_VERISURE_TOKEN_FILE    |               | Token file for Verisure login. See [Create Verisure token](#create-verisure-token). |

## Example docker-compose.yaml

```yaml
version: "3.5"

services:
  verisure2mqtt:
    container_name: verisure2mqtt
    image: paulianttila/verisure2mqtt:2.0.0
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    environment:
      - CFG_LOG_LEVEL=DEBUG
      - CFG_MQTT_BROKER_URL=127.0.0.1
      - CFG_MQTT_BROKER_PORT=1883
      - CFG_VERISURE_USERNAME=<username>
      - CFG_VERISURE_PASSWORD=<password>
      - CFG_VERISURE_TOKEN_FILE=/app/.verisure-cookie
    volumes:
      # Create with vsure mfa option
      - ./.verisure-cookie:/app/.verisure-cookie
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/healthy"]
      interval: 60s
      timeout: 3s
      start_period: 5s
      retries: 3
 ```


 # Create Verisure token

Cretae empty file

```bash
touch .verisure-cookie
```

Run shell
```bash
docker-compose run verisure2mqtt sh
```

Create token (give code received by the text message from Verisure)
```bash
vsure $CFG_VERISURE_USERNAME $CFG_VERISURE_PASSWORD mfa 
```