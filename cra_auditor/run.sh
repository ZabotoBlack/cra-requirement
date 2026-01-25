#!/usr/bin/with-contenv bashio

echo "Starting CRA Compliance Auditor Add-on..."

# 1. Verify the frontend directory exists BEFORE starting python
if [ ! -d "/app/dist" ]; then
    bashio::log.error "Directory /app/dist does not exist! Check your Dockerfile copy command."
    ls -R /app
else
    echo "Found /app/dist, content check:"
    ls -la /app/dist
fi

echo "Checking build directory..."
ls -F /app

# 2. Start the web server with unbuffered output (-u)
echo "Starting web server on port 8099..."
python3 -u /app/server.py &
SERVER_PID=$!

# Read config from Home Assistant Supervisor
TARGET_SUBNET=$(bashio::config 'target_subnet')
echo "Target Subnet for scanning: $TARGET_SUBNET"

# 3. Start scanning logic with unbuffered output
echo "Starting scanning process..."
python3 -u /app/scan_logic.py --subnet "$TARGET_SUBNET" &
SCAN_PID=$!

# 4. Monitor processes
# If server.py dies, we want the container to exit so we know something is wrong.
wait -n $SERVER_PID $SCAN_PID

# Exit with status of process that exited first
exit $?