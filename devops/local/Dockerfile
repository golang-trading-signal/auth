FROM golang:1.17
# Add a work directory
WORKDIR /app
# Cache and install dependencies
COPY go.mod go.sum ./
RUN go mod download -x
# Copy app files
COPY . .

# Install Reflex for development
RUN go install github.com/mitranim/gow@latest

EXPOSE 8000