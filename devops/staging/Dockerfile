FROM golang:1.17
# Add a work directory
WORKDIR /app
# Cache and install dependencies
COPY go.mod go.sum ./
RUN go mod download
# Copy app files
COPY . .
RUN ls
RUN pwd
RUN which go
RUN go build main.go

EXPOSE 8000