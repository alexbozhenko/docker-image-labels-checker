# Docker Image Labels Checker

Vibe-coded script to check container images for OCI labels.

## Motivation

Many Docker Official Images lack [OCI image labels](https://github.com/opencontainers/image-spec/blob/main/annotations.md). As of November 2025, only 54 out of 178 official images have OCI labels set. See [current state of OCI labels in Docker Official Images](https://gist.github.com/alexbozhenko/108f9c9863e1e8dfdd1de8981249094d#file-gistfile1-txt-L860-L864) for details.

This tool helps identify which images have metadata labels.

```bash
# Check all official images for OCI labels
docker-image-labels-checker --official-images | docker-image-labels-checker --json > results.json
```

## Installation

```bash
go install github.com/alexbozhenko/docker-image-labels-checker@latest
```

## Usage

```bash
# Check Docker Hub official images (assumes :latest if no tag)
docker-image-labels-checker golang python node

# Check with specific tags
docker-image-labels-checker golang:1.23 python:3.12-slim node:20-alpine

# Check non-official images
docker-image-labels-checker synadia/nats-server:nightly traefik/traefik:v3.0

# Check images from other registries
docker-image-labels-checker ghcr.io/owner/repo:tag gcr.io/project/image:v1.0

# List all Docker Official Images
docker-image-labels-checker --official-images

# JSON output
docker-image-labels-checker --json golang python

# Read from file
docker-image-labels-checker --file images.txt

# Pipe from stdin
docker-image-labels-checker --official-images | docker-image-labels-checker --json

# Use authentication to avoid rate limits
docker-image-labels-checker --auth golang python
```

## Output

### JSON Output

```json
{
  "results": [
    {
      "name": "traefik",
      "labels": {
        "org.opencontainers.image.description": "A modern reverse-proxy",
        "org.opencontainers.image.source": "https://github.com/traefik/traefik",
        "org.opencontainers.image.title": "Traefik",
        "org.opencontainers.image.url": "https://traefik.io",
        "org.opencontainers.image.vendor": "Traefik Labs",
        "org.opencontainers.image.version": "v3.6.1"
      }
    },
    {
      "name": "golang"
    }
  ],
  "summary": {
    "with_labels": 1,
    "without_labels": 1,
    "errors": 0,
    "images_with_labels": ["traefik"],
    "images_without_labels": ["golang"]
  },
  "tag": "latest",
  "checked": 2
}
```

## Authentication

By default, the tool runs without authentication (subject to Docker Hub rate limits: 100 pulls/6h).

To use authentication and avoid rate limits, use the `--auth` flag. The tool will read Docker credentials from `~/.docker/config.json`:

```bash
docker login
docker-image-labels-checker --auth golang python
```

Supports credential stores: `pass`, `secretservice`, `osxkeychain`, etc.

See [Docker Hub rate limit documentation](https://docs.docker.com/docker-hub/usage/pulls/) for details (100 pulls/6h anonymous, 200 pulls/6h authenticated).

**Note:** After running the tool, pulled images remain in your local Docker cache. To clean them up, use:

```bash
docker image prune -a
```

See [docker image prune documentation](https://docs.docker.com/reference/cli/docker/image/prune/) for more options.

## License

MIT
