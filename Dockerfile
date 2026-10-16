# The release image: the static Linux kseal binary on a distroless base, which
# carries the CA certificates kseal needs to reach Google Cloud. The release
# workflow builds it from the attested musl binary placed next to this file.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY kseal /kseal

ENTRYPOINT ["/kseal"]
