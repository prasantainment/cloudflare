# Step 1: Use the official Golang image to build the Go service
FROM golang:1.23 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and source code
COPY go.mod go.sum ./
RUN go mod tidy
     
# Copy the rest of the application code
COPY . .

# Expose the port the app will run on
EXPOSE 8080

# Set the entrypoint to run the Go application, using flags for configuration
CMD ["go", "run", "cmd/main.go"]    