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

export GEMINI_API_KEY=$(bashio::config 'gemini_api_key')

if [ -z "$GEMINI_API_KEY" ]; then
    bashio::log.warning "Gemini API Key is not set. AI features will be disabled."
else
    bashio::log.info "Gemini API Key found. AI features enabled."
fi

exec python3 -u /app/server.py