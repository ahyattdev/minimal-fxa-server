FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /minimal-fxa-server .

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /minimal-fxa-server /minimal-fxa-server

EXPOSE 80

ENTRYPOINT ["/minimal-fxa-server"]

