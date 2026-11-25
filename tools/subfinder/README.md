# Build passivo do subfinder

O runner aceita o perfil `2.17.0-prometheus-passive.1`. Este build usa a fonte HackerTarget do subfinder e uma entrada dedicada que aceita somente o argv do runner. Cada processo pode consultar uma vez o endpoint HTTPS definido no patch. O cliente verifica TLS, recusa redirects e devolve os códigos 29 e 53 diante de HTTP 429 e 503. O teste do patch usa um transporte simulado.

Use Go 1.27.4 e aplique [o patch](2.17.0-prometheus-passive.1.patch) sobre o commit oficial da [release v2.17.0](https://github.com/projectdiscovery/subfinder/commit/c97f25802892093060f0fc424bfc3f39e273693a).

```sh
set -eu
prometheus_root=$(pwd)
build_dir=$(mktemp -d)
git clone --depth 1 --branch v2.17.0 https://github.com/projectdiscovery/subfinder.git "$build_dir/src"
cd "$build_dir/src"
test "$(git rev-parse HEAD)" = c97f25802892093060f0fc424bfc3f39e273693a
git apply --check "$prometheus_root/tools/subfinder/2.17.0-prometheus-passive.1.patch"
git apply "$prometheus_root/tools/subfinder/2.17.0-prometheus-passive.1.patch"
GOTOOLCHAIN=local go mod download
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOAMD64=v1 go test -mod=readonly ./cmd/subfinder
GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOAMD64=v1 \
  go build -mod=readonly -trimpath -buildvcs=false -o "$build_dir/subfinder" ./cmd/subfinder
sha256sum "$build_dir/subfinder"
```

Instale o ELF em um caminho absoluto administrado no FX-6300. Revise o build e registre seu SHA-256 no [manifesto de ferramentas](../../examples/tools-manifest.yaml). O CI Rust usa um ELF sintético e roda sem baixar ou compilar o subfinder.
