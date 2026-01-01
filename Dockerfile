FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /minimal-fxa-server .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /fxa-user ./cmd/fxa-user

FROM alpine:3.23

LABEL org.opencontainers.image.source=https://github.com/ahyattdev/minimal-fxa-server

COPY --from=builder /minimal-fxa-server /usr/local/bin/minimal-fxa-server
COPY --from=builder /fxa-user /usr/local/bin/fxa-user

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/minimal-fxa-server"]
