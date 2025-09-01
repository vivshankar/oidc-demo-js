#!/bin/bash
#
# Script to download a GitHub release zipball and unpack it
# Usage: ./download_github_release.sh owner/repo tag [output_dir]
#
# Example: ./download_github_release.sh kubernetes/kubectl v1.28.0 ./

set -e

# Function to display usage information
usage() {
  echo "Usage: $0 owner/repo tag [output_dir]"
  echo ""
  echo "Arguments:"
  echo "  owner/repo   GitHub repository (e.g., kubernetes/kubectl)"
  echo "  tag          Release tag (e.g., v1.0.0, latest)"
  echo "  output_dir   Optional: Directory to extract files to (default: current directory)"
  echo ""
  echo "Example: $0 kubernetes/kubectl v1.28.0 ./"
  exit 1
}

# Check if required arguments are provided
if [ $# -lt 2 ]; then
  usage
fi

# Parse arguments
REPO="$1"
TAG="$2"
OUTPUT_DIR="${3:-.}"  # Default to current directory if not specified
TEMP_ZIP="release.zip"  # Temporary zip file name

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Downloading zipball from $REPO release $TAG..."

# Construct the GitHub API URL for the release
if [ "$TAG" = "latest" ]; then
  API_URL="https://api.github.com/repos/$REPO/releases/latest"
else
  API_URL="https://api.github.com/repos/$REPO/releases/tags/$TAG"
fi

# Get the zipball_url from the release
echo "Fetching release information..."
API_RESPONSE=$(curl -s "$API_URL")

# Enable debug mode if DEBUG environment variable is set
if [ ! -z "$DEBUG" ]; then
  echo "DEBUG: API Response:"
  echo "$API_RESPONSE" | head -30
fi

# First try: direct zipball_url
ZIPBALL_URL=$(echo "$API_RESPONSE" | grep -o "\"zipball_url\":\"[^\"]*\"" | head -1 | cut -d'"' -f4)

if [ -z "$ZIPBALL_URL" ]; then
  echo "Direct zipball_url not found, trying alternative methods..."
  
  # Second try: archive_url template
  ARCHIVE_URL=$(echo "$API_RESPONSE" | grep -o "\"archive_url\":\"[^\"]*\"" | head -1 | cut -d'"' -f4)
  if [ ! -z "$ARCHIVE_URL" ]; then
    # Replace {archive_format} with zip and {/ref} with nothing
    ZIPBALL_URL=$(echo "$ARCHIVE_URL" | sed 's/{archive_format}/zipball/g' | sed 's/{\/ref}//g')
    echo "Using archive_url template: $ZIPBALL_URL"
  fi
  
  # Third try: direct URL construction
  if [ -z "$ZIPBALL_URL" ]; then
    ZIPBALL_URL="https://github.com/$REPO/zipball/$TAG"
    echo "Constructing direct GitHub zipball URL: $ZIPBALL_URL"
  fi
fi

if [ -z "$ZIPBALL_URL" ]; then
  echo "Error: Could not determine zipball URL for release '$TAG'"
  exit 1
fi

# Download the zipball
echo "Downloading from $ZIPBALL_URL..."
curl -L -o "$OUTPUT_DIR/$TEMP_ZIP" "$ZIPBALL_URL"

if [ $? -ne 0 ]; then
  echo "Error: Failed to download the zipball"
  exit 1
fi

echo "Download complete. Unpacking zip file..."

# Unzip the downloaded file
unzip -o "$OUTPUT_DIR/$TEMP_ZIP" -d "$OUTPUT_DIR"

if [ $? -ne 0 ]; then
  echo "Error: Failed to unpack the zip file"
  exit 1
fi

# Clean up the temporary zip file
rm "$OUTPUT_DIR/$TEMP_ZIP"

echo "Successfully downloaded and unpacked release zipball to $OUTPUT_DIR"

# Made with Bob
