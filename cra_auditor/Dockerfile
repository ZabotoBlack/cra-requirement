ARG BUILD_FROM
FROM $BUILD_FROM

# Install system dependencies for both frontend and backend
RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    nmap-scripts \
    iputils \
    nodejs \
    npm

WORKDIR /app

# Install frontend dependencies and build the static UI
# This is done in layers to improve Docker build caching
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Executable permissions
RUN chmod a+x /app/run.sh

CMD [ "/app/run.sh" ]