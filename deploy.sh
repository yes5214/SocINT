#!/bin/bash
# Discord Security Bot - Quick Deployment Script
# Automates Docker deployment process

set -e  # Exit on error

echo "========================================"
echo "Discord Security Bot - Docker Deployment"
echo "========================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed!${NC}"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed!${NC}"
    echo "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✅ Docker and Docker Compose found${NC}"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file not found${NC}"
    if [ -f .env.example ]; then
        echo "Creating .env from .env.example..."
        cp .env.example .env
        echo -e "${GREEN}✅ .env file created${NC}"
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT: Edit .env and add your tokens!${NC}"
        echo "   - DISCORD_TOKEN=your_token_here"
        echo "   - VT_API_KEY=your_virustotal_key_here"
        echo ""
        read -p "Press Enter after editing .env to continue..."
    else
        echo -e "${RED}❌ .env.example not found!${NC}"
        exit 1
    fi
fi

# Validate .env has required variables
source .env
if [ -z "$DISCORD_TOKEN" ] || [ "$DISCORD_TOKEN" == "your_discord_bot_token_here" ]; then
    echo -e "${RED}❌ DISCORD_TOKEN not set in .env!${NC}"
    exit 1
fi

echo -e "${GREEN}✅ .env file configured${NC}"
echo ""

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p logs
mkdir -p quarantine_storage
chmod 700 quarantine_storage
chmod 755 logs
echo -e "${GREEN}✅ Directories created${NC}"
echo ""

# Check if YARA rules exist
if [ ! -f rules.yar ]; then
    echo -e "${YELLOW}⚠️  rules.yar not found!${NC}"
    if [ -f build_yara_rules.sh ]; then
        echo "Building YARA rules..."
        bash build_yara_rules.sh
        echo -e "${GREEN}✅ YARA rules built${NC}"
    else
        echo -e "${RED}❌ Cannot build YARA rules - build_yara_rules.sh not found${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ YARA rules found${NC}"
fi
echo ""

# Check if custom signatures exist
if [ ! -f custom_signatures.json ]; then
    echo -e "${RED}❌ custom_signatures.json not found!${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Custom signatures found${NC}"
echo ""

# Show current threshold configuration
echo "Detection Threshold Configuration:"
echo "  URL Detection: ${URL_DETECTION_THRESHOLD:-25} (default: 25)"
echo "  File Detection: ${FILE_DETECTION_THRESHOLD:-15} (default: 15)"
echo ""
echo "Based on testing:"
echo "  - URL threshold 25 = 90% accuracy ✅"
echo "  - File threshold 15 = Better malware detection ⚠️"
echo ""

# Ask user what to do
echo "What would you like to do?"
echo "  1) Build and start bot (fresh deployment)"
echo "  2) Rebuild and restart bot (after code changes)"
echo "  3) Start bot (already built)"
echo "  4) Stop bot"
echo "  5) View logs"
echo "  6) Run tests"
echo "  7) Exit"
echo ""
read -p "Enter choice [1-7]: " choice

case $choice in
    1)
        echo ""
        echo "Building Docker image..."
        docker-compose build
        echo ""
        echo "Starting bot..."
        docker-compose up -d
        echo ""
        echo -e "${GREEN}✅ Bot deployed successfully!${NC}"
        echo ""
        echo "View logs with: docker-compose logs -f"
        echo "Stop bot with: docker-compose down"
        ;;
    2)
        echo ""
        echo "Stopping current bot..."
        docker-compose down
        echo ""
        echo "Rebuilding Docker image..."
        docker-compose build --no-cache
        echo ""
        echo "Starting bot..."
        docker-compose up -d
        echo ""
        echo -e "${GREEN}✅ Bot rebuilt and restarted!${NC}"
        echo ""
        echo "View logs with: docker-compose logs -f"
        ;;
    3)
        echo ""
        echo "Starting bot..."
        docker-compose up -d
        echo ""
        echo -e "${GREEN}✅ Bot started!${NC}"
        echo ""
        echo "View logs with: docker-compose logs -f"
        ;;
    4)
        echo ""
        echo "Stopping bot..."
        docker-compose down
        echo ""
        echo -e "${GREEN}✅ Bot stopped!${NC}"
        ;;
    5)
        echo ""
        echo "Showing logs (Ctrl+C to exit)..."
        docker-compose logs -f
        ;;
    6)
        echo ""
        echo "Running tests..."
        echo ""
        echo "1. Testing URL Scanner..."
        docker-compose exec discord-security-bot python test_real_urls.py || true
        echo ""
        echo "2. Testing File Scanner..."
        docker-compose exec discord-security-bot python test_real_samples.py || true
        echo ""
        echo -e "${GREEN}✅ Tests complete!${NC}"
        echo "See FINAL_TEST_RESULTS.md for detailed analysis"
        ;;
    7)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid choice!${NC}"
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo "Deployment complete!"
echo "========================================"
echo ""
echo "Useful commands:"
echo "  - View logs:       docker-compose logs -f"
echo "  - Stop bot:        docker-compose down"
echo "  - Restart bot:     docker-compose restart"
echo "  - Check status:    docker-compose ps"
echo "  - Run tests:       docker-compose exec discord-security-bot python test_real_urls.py"
echo ""
echo "See DOCKER_DEPLOYMENT.md for full documentation"
echo ""
