# Build Stage
FROM ubuntu@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz \
    && rm -f go1.23.2.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN go install github.com/tomnomnom/qsreplace@latest

FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt update && apt install git -y && apt clean && rm -rf /var/lib/apt/lists/*
# Copy Go binaries and tools from the build stage
COPY --from=build /root/go/bin /root/go/bin

# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.5.2
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL} uro
WORKDIR /app/service
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /app/sqlmap
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

COPY sqlmapm /app/service/sqlmapm
CMD [ "python", "-m", "sqlmapm" ]