FROM paulianttila/mqtt-framework:1.1.1

ARG DIR=/app
ARG APP=app.py

ARG USER=app
ARG GROUP=app

ENV DIR=${DIR}
ENV APP=${APP}

COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

RUN mkdir -p ${DIR}
WORKDIR ${DIR}
COPY src ${DIR}

RUN addgroup -S ${GROUP} && adduser -S ${USER} -G ${GROUP}

VOLUME /data
WORKDIR /data

USER ${USER}
CMD python ${DIR}/${APP}