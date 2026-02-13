ARG BUILD_FROM

# ---- Stage 1: Build frontend with Node.js ----
FROM $BUILD_FROM AS frontend-builder

RUN apk add --no-cache nodejs npm

WORKDIR /build

# Install frontend dependencies (cached layer)
COPY package.json package-lock.json ./
RUN npm ci --no-audit

# Copy source and build
COPY . .
RUN npm run build

# ---- Stage 2: Production image (Python only, no Node.js runtime) ----
FROM $BUILD_FROM

RUN apk add --no-cache \
    python3 \
    py3-pip \
    nmap \
    nmap-scripts \
    iputils

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

# Copy backend source
COPY *.py ./
COPY run.sh ./

# Copy built frontend from Stage 1
COPY --from=frontend-builder /build/dist ./dist

# Executable permissions
RUN chmod a+x /app/run.sh

CMD [ "/app/run.sh" ]