FROM golang:1.25.0 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o fleet-management ./cmd/server/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/fleet-management .
CMD ["./fleet-management"]