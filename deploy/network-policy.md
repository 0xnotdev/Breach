# Network egress policy

## Required production rule

The scanner worker is default-denied for outbound traffic. It may reach only:

- the internal PostgreSQL service on TCP 5432;
- the internal egress proxy on TCP 3128;
- cluster DNS on UDP/TCP 53 when the runtime requires it.

The egress proxy is the only component with an external route. It permits HTTP `CONNECT` only to `api.github.com:443` and `api.osv.dev:443`; it denies plain HTTP forwarding, other ports, IP literals, userinfo, suffix/prefix lookalikes, and every other hostname. TLS remains end-to-end between Node and the approved service. Neither repository metadata nor repository content can add a destination.

The ordinary Docker bridge named `egress` is not a destination allowlist. It gives the proxy external connectivity; the worker is deliberately absent from it and joins only the internal `metadata` and `proxy_control` networks. `NODE_USE_ENV_PROXY=1` makes the Node 24 global fetch stack honor `HTTPS_PROXY`, while `NO_PROXY` keeps loopback/internal health traffic local. A compromise of the proxy process itself remains a local residual risk.

## Production enforcement

Production must combine the application `EgressPolicy` with a default-deny network policy and an audited L7/FQDN-aware egress gateway. Standard Kubernetes `NetworkPolicy` is L3/L4 and cannot express a stable hostname allowlist by itself. The exact effective policy is:

1. Select the Breach worker pods and deny all egress by default.
2. Permit worker egress only to the PostgreSQL pod/service on TCP 5432, the egress-gateway pods on TCP 3128, and the cluster DNS pods on UDP/TCP 53.
3. Permit the egress gateway to resolve DNS and establish TCP 443 only when the TLS tunnel authority/FQDN is exactly `api.github.com` or `api.osv.dev`.
4. Deny IP literals, wildcard subdomains, redirects outside the two names, all other ports/protocols, and direct worker internet routes.
5. Alert on denied attempts and on any worker pod with an interface/default route outside the approved internal networks.

The deployable example is [`deploy/cilium-egress-policy.yaml`](./cilium-egress-policy.yaml). It uses `toEndpoints` for PostgreSQL/DNS/proxy and `toFQDNs.matchName` entries for the two exact external names on the gateway pod. The workload labels and `breach` namespace in that file are mandatory inputs; update both policy and manifests together if they change. For another CNI/cloud firewall, use its equivalent FQDN-aware egress control; resolve-to-IP rules must be continuously reconciled because provider addresses change. Verify the CNI actually enforces policy before launch—creating a Kubernetes `NetworkPolicy` object is insufficient when the installed network plugin does not implement it.

References: [Node environment proxy support](https://nodejs.org/api/cli.html#node_use_env_proxy1), [Docker internal networks](https://docs.docker.com/reference/compose-file/networks/#internal), and [Kubernetes NetworkPolicy behavior](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

## Verification

- From the worker, `CONNECT example.com:443`, direct IP access, and direct HTTPS without the proxy must fail.
- Through the proxy, `api.github.com:443` and `api.osv.dev:443` must establish TLS, while port 80/444 and lookalike names fail.
- Inspect container network membership: only `egress-proxy` may join the external `egress` bridge.
- Re-run the repository-controlled URL regression and the full verification suite after any transport, proxy, CNI, DNS, or firewall change.
