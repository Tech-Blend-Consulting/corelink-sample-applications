FROM golang:1.26.10-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o /customer-app .

FROM alpine:3.24.3
RUN apk add --no-cache ca-certificates && adduser -D -u 10002 app
COPY --from=builder /customer-app /usr/local/bin/customer-app
USER app
EXPOSE 5051
CMD ["customer-app"]
