FROM golang:tip-trixie


WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

RUN go get github.com/swaggo/swag/cmd/swag@latest

RUN go install github.com/swaggo/swag/cmd/swag@latest

RUN export PATH=$PATH:/root/go/bin

# Build the binary with optimizations
#RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Runtime stage
#FROM alpine:latest

# RUN apt install -y ca-certificates

#WORKDIR /root/

# Copy the binary from builder
#COPY /app/main .

EXPOSE 8080

CMD ["bash", "/app/run.sh"]
