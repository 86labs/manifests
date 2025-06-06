# Istio-CNI

This uses istio-cni as described here <https://istio.io/latest/docs/setup/additional-setup/cni/>.

This configuration also enables native sidecars for Istio through the `ENABLE_NATIVE_SIDECARS=true` environment variable in istiod. Native sidecars (introduced in Kubernetes 1.28 as an alpha feature) help address issues with init containers and application lifecycle management. Learn more about native sidecars at <https://istio.io/latest/blog/2023/native-sidecars/>.

With native sidecars enabled, init containers should be able to access the network through the Istio proxy. However, if you still encounter issues with KServe and init containers, you can refer to <https://istio.io/latest/docs/setup/additional-setup/cni/#compatibility-with-application-init-containers> and either:

1. Use `runAsUser: 1337` in your init containers, OR
2. Add the annotation `traffic.sidecar.istio.io/excludeOutboundIPRanges: 0.0.0.0/0` to your KServe inferenceservices.

## Upgrade Istio Manifests

Istio ships with an installer called `istioctl`, which is a deployment /
debugging / configuration management tool for Istio all in one package.
In this section, we explain how to upgrade our istio kustomize packages
by leveraging `istioctl`. Assuming the new version is `X.Y.Z` and the
old version is `X1.Y1.Z1`:

1. Make a copy of the old istio manifests tree, which will become the
    kustomization for the new Istio version:

        export MANIFESTS_SRC=<path/to/manifests/repo>
        export ISTIO_OLD=$MANIFESTS_SRC/common/istio-cni-X1-Y1
        export ISTIO_NEW=$MANIFESTS_SRC/common/istio-cni-X-Y
        cp -a $ISTIO_OLD $ISTIO_NEW

2. Download `istioctl` for version `X.Y.Z`:

        $ ISTIO_VERSION="X.Y.Z"
        $ wget "https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istio-${ISTIO_VERSION}-linux-amd64.tar.gz"
        $ tar xvfz istio-${ISTIO_VERSION}-linux-amd64.tar.gz
        # sudo mv istio-${ISTIO_VERSION}/bin/istioctl /usr/local/bin/istioctl

3. Generate manifests and add them to their respective packages. We
    will generate manifests using `istioctl`, the
    `profile.yaml` file from upstream and the
    `profile-overlay.yaml` file that contains our desired
    changes:

        export PATH="$MANIFESTS_SRC/scripts:$PATH"
        cd $ISTIO_NEW
        istioctl manifest generate --cluster-specific -f profile.yaml -f profile-overlay.yaml --set components.cni.enabled=true --set components.cni.namespace=kube-system > dump.yaml
        ./split-istio-packages -f dump.yaml
        mv $ISTIO_NEW/crd.yaml $ISTIO_NEW/istio-crds/base
        mv $ISTIO_NEW/install.yaml $ISTIO_NEW/istio-install/base
        mv $ISTIO_NEW/cluster-local-gateway.yaml $ISTIO_NEW/cluster-local-gateway/base
        rm dump.yaml

    ---
    **NOTE**

    `split-istio-packages` is a python script in the same folder as this file.
    The `ruamel.yaml` version used is 0.16.12.

    `--cluster-specific` is a flag that determines if a current K8s cluster context will be used to dynamically detect default settings. Ensure you have a target cluster ready before running the above commands.
    We target Kubernetes 1.32+ for compatibility. The `--cluster-specific` flag helps ensure generated resources are compatible with your cluster version and configuration.

    ---

## Changes to Istio's upstream manifests

### Changes to the upstream IstioOperator profile

Changes to Istio's upstream profile `default` are the following:

- Add a `cluster-local-gateway` component for Kserve. Knative-local-gateway is now obsolete <https://github.com/kubeflow/manifests/pull/2355/commits/adc00b804404ea08685a044ae595be0bed9adb59>.
- Disable the EgressGateway component. We do not use it and it adds unnecessary complexity.

Those changes are captured in the [profile-overlay.yaml](profile-overlay.yaml)
file.

### Changes to the upstream manifests using kustomize

The Istio kustomizations make the following changes:

- Remove PodDisruptionBudget from `istio-install` and `cluster-local-gateway` kustomizations. See:
  - <https://github.com/istio/istio/issues/12602>
  - <https://github.com/istio/istio/issues/24000>
- Add Istio AuthorizationPolicy to allow all requests to the Istio Ingressgateway and the Istio cluster-local gateway.
- Add Istio AuthorizationPolicy in Istio's root namespace, so that sidecars deny traffic by default (explicit deny-by-default authorization model).
- Add Gateway CRs for the Istio Ingressgateway and the Istio cluster-local gateway, as `istioctl` stopped generating them in later versions.
- Add the istio-system namespace object to `istio-namespace`, as `istioctl` stopped generating it in later versions.
- Configure TCP KeepAlives.
- Disable tracing as it causes DNS breakdown. See:
  <https://github.com/istio/istio/issues/29898>
- Set ENABLE_DEBUG_ON_HTTP=false according to <https://istio.io/latest/docs/ops/best-practices/security/#control-plane>
