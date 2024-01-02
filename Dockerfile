# syntax=docker/dockerfile:1

FROM golang:1.21.5
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build ./cmd/certspotter/ -o certspotter

FROM alpine:3.19.0@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48
COPY --from=0 /app/certspotter /usr/local/bin/certspotter