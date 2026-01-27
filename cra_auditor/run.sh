#!/usr/bin/with-contenv bashio

echo "Starting CRA Compliance Auditor Add-on..."

# 1. Verify the frontend directory exists (optional check, good for debugging)
if [ ! -d "/app/dist" ]; then
    bashio::log.warning "Directory /app/dist not found. Ensure frontend is built."
else
    echo "Found /app/dist"
fi

# 2. Start the Flask server
# Flask handles serving the static files and the API
echo "Starting Flask server on port 8099..."
exec python3 -u /app/server.py