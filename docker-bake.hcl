// Build definition for the one mailout image.
//
// The operator and the dataplane are the same binary with different
// subcommands, so there is one image and the operator deploys itself for the
// gateways — see the MAILOUT_GATEWAY_IMAGE replacement in config/default.
//
// Normalised to the maitredede/ci `bake-images` contract: REGISTRY / TAG /
// EXTRA_TAG / PLATFORMS are auto-bound by bake from the job environment, one
// target per image named exactly like the image.
//
// Both architectures on purpose. The cluster is three arm64 workers and one
// amd64, and the operator runs two replicas with only a preferred
// anti-affinity — a single-arch image means one replica looping on `exec format
// error`, so pinning the Deployment to an architecture would be the only way
// out. The Dockerfile cross-compiles (BUILDPLATFORM plus GOARCH), so each
// BuildKit node builds natively for its own target rather than under QEMU.
//
// Local use, against the split-horizon registry:
//   TAG=$(git describe --tags --always) docker buildx bake --push

variable "REGISTRY" {
  default     = "dkr.daly.nc/mailout"
  description = "Image name prefix: registry host + project"
}

variable "TAG" {
  default     = "dev"
  description = "Primary tag"
}

variable "EXTRA_TAG" {
  default     = ""
  description = "Secondary tag, empty for none"
}

variable "PLATFORMS" {
  default = "linux/amd64,linux/arm64"
}

function "tags" {
  params = [image]
  result = concat(
    ["${REGISTRY}/${image}:${TAG}"],
    EXTRA_TAG == "" ? [] : ["${REGISTRY}/${image}:${EXTRA_TAG}"],
  )
}

group "default" {
  targets = ["operator"]
}

target "operator" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = split(",", PLATFORMS)
  tags       = tags("operator")
  // Stamped into the binary, so `mailout version` reports what was built rather
  // than the dev default. The Dockerfile always passed this ldflag, but until
  // main.version existed go build discarded it silently — one image serves both
  // roles and the operator hands its own image to every gateway, so a stale tag
  // propagates without a word.
  args = { VERSION = TAG }
  labels = {
    "org.opencontainers.image.source"  = "https://github.com/maitredede/mailout-operator"
    "org.opencontainers.image.version" = TAG
  }
}
