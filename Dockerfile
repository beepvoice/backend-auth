# FROM rust:1.32 as build
FROM alpine:3.9 AS build

RUN apk add --no-cache gcc musl-dev
RUN apk add --no-cache rust cargo

# RUN rustup target add x86_64-unknown-linux-musl

# Create new empty shell project
RUN USER=root cargo new --bin app
WORKDIR /app

# Copy over Cargo.toml
COPY ./Cargo.toml ./Cargo.toml

# Change target env
ENV RUSTFLAGS="-C target-cpu=native"
# ENV RUSTFLAGS="-C target-cpu=x86_64_alpine-linux-musl"
# Run build step to cache dependencies
RUN cargo build --release
RUN rm src/*.rs

# Copy over src files
COPY ./src/main.rs ./src/main.rs

# Build for release
RUN rm ./target/release/deps/backend_auth*
RUN cargo build --release

# Copy over .env
COPY ./.env ./.env

FROM alpine:3.9

RUN apk add --no-cache gcc

COPY --from=build /app/target/release .
COPY --from=build /app/.env .env

ENTRYPOINT ["./backend-auth"]
