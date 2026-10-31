
#!/bin/bash
set -e

cd "$(dirname "$0")"
export PYTHONPATH="$PWD"

echo "Starting Vulnerability Assessment Lab..."

# Check Docker
if ! docker info >/dev/null 2>&1; then
    echo "Please start Docker Desktop first."
    exit 1
fi

# Start or create OWASP Juice Shop
if docker container inspect juice-shop >/dev/null 2>&1; then
    docker start juice-shop >/dev/null
else
    docker run -d --name juice-shop \
      -p 127.0.0.1:3000:3000 \
      bkimminich/juice-shop
fi

# Activate Python environment
if [ ! -f venv/bin/activate ]; then
    echo "Python virtual environment not found."
    exit 1
fi

source venv/bin/activate

echo "Juice Shop: http://127.0.0.1:3000"
echo "Scanner: http://127.0.0.1:5000"
echo "Mini WAF: http://127.0.0.1:8080"


# Check existing services
if curl -fsS --max-time 3 http://127.0.0.1:5000/ >/dev/null 2>&1 &&
   curl -fsS --max-time 3 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    echo "Scanner and Mini WAF are already running."
else
    if lsof -nP -iTCP:5000 -sTCP:LISTEN | grep -q LISTEN ||
       lsof -nP -iTCP:8080 -sTCP:LISTEN | grep -q LISTEN; then
        echo "Port 5000 or 8080 is occupied. Check running services."
        exit 1
    fi

    echo "Starting Scanner and Mini WAF..."
    bash run_lab.sh all
fi

