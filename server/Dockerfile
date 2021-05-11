FROM rustlang/rust:nightly as build

ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /usr/src/share-server

COPY . .

RUN cargo install --path .

FROM gcr.io/distroless/cc-debian10

COPY --from=build /usr/local/cargo/bin/share-server /usr/local/bin/share-server

CMD ["share-server"]