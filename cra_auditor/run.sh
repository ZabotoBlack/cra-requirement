#!/usr/bin/with-contenv bashio

echo "Starting CRA Compliance Auditor Add-on..."

# 1. Verify the frontend directory exists (optional check, good for debugging)
if [ ! -d "/app/dist" ]; then
    bashio::log.warning "Directory /app/dist not found. Ensure frontend is built."
else
    echo "Found /app/dist"
fi


# 2. Export Gemini API key if configured
GEMINI_API_KEY=$(bashio::config 'gemini_api_key')
gemini_config_status=$?
if [ $gemini_config_status -ne 0 ]; then
    bashio::log.error "Failed to read gemini_api_key from add-on config (exit: $gemini_config_status)."
    exit $gemini_config_status
fi
export GEMINI_API_KEY

NVD_API_KEY=$(bashio::config 'nvd_api_key')
nvd_config_status=$?
if [ $nvd_config_status -ne 0 ]; then
    bashio::log.error "Failed to read nvd_api_key from add-on config (exit: $nvd_config_status)."
    exit $nvd_config_status
fi
export NVD_API_KEY

LOG_LEVEL=$(bashio::config 'log_level')
log_level_config_status=$?
if [ $log_level_config_status -ne 0 ]; then
    bashio::log.error "Failed to read log_level from add-on config (exit: $log_level_config_status)."
    exit $log_level_config_status
fi

LOG_LEVEL=$(echo "$LOG_LEVEL" | tr '[:upper:]' '[:lower:]')
case "$LOG_LEVEL" in
    trace|debug|scan_info|info|warning|error|fatal)
        ;;
    *)
        bashio::log.warning "Invalid log_level '$LOG_LEVEL'. Falling back to 'info'."
        LOG_LEVEL="info"
        ;;
esac
export LOG_LEVEL

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

bashio::log.info "Backend log level set to: $LOG_LEVEL"

# 3. Start production WSGI server (gunicorn replaces Flask dev server)
exec gunicorn \
    --bind 0.0.0.0:8099 \
    --workers 2 \
    --threads 2 \
    --timeout 300 \
    --access-logfile - \
    --error-logfile - \
    server:app