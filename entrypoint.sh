#!/bin/sh
set -e

echo "Starting aithen..."

# Start the application in background
./aithen &
APP_PID=$!

# Wait for certificate to be generated (max 30 seconds)
echo "Waiting for certificate generation..."
COUNTER=0
while [ ! -f /certs/token.crt ] && [ $COUNTER -lt 30 ]; do
    sleep 1
    COUNTER=$((COUNTER + 1))
done

if [ -f /certs/token.crt ]; then
    echo "Certificate found at /certs/token.crt"
    ls -l /certs/token.crt
else
    echo "Warning: Certificate not generated within 30 seconds"
fi

# Wait for the application process
wait $APP_PID

