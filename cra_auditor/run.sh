#!/usr/bin/with-contenv bashio

echo "Starting CRA Compliance Auditor Add-on..."

# 1. Verify the frontend directory exists (optional check, good for debugging)
if [ ! -d "/app/dist" ]; then
    bashio::log.warning "Directory /app/dist not found. Ensure frontend is built."
else
    echo "Found /app/dist"
fi


# 2. Export Gemini API key if configured
export GEMINI_API_KEY=$(bashio::config 'gemini_api_key')
export NVD_API_KEY=$(bashio::config 'nvd_api_key')

if [ -z "$GEMINI_API_KEY" ]; then
    bashio::log.warning "Gemini API Key is not set. AI features will be disabled."
else
    bashio::log.info "Gemini API Key found. AI features enabled."
fi

if [ -z "$NVD_API_KEY" ]; then
    bashio::log.warning "NVD API Key is not set. Vulnerability lookups may be throttled."
else
    bashio::log.info "NVD API Key found. Vulnerability lookups optimized."
fi

# 3. Start production WSGI server (gunicorn replaces Flask dev server)
exec gunicorn \
    --bind 0.0.0.0:8099 \
    --workers 2 \
    --threads 2 \
    --timeout 300 \
    --access-logfile - \
    --error-logfile - \
    server:app