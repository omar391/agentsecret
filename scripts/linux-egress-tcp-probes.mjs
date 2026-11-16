import { connect, isIP } from "node:net";

export function tcpBypassTargets(environment) {
  const ipv4Targets = [
    environment.SUPERVISOR_EXTERNAL_IP,
    environment.ORIGIN_EXTERNAL_IP,
    environment.INTERNAL_GATEWAY_IP,
  ];
  const ipv6Targets = [
    environment.SUPERVISOR_EXTERNAL_IPV6,
    environment.ORIGIN_EXTERNAL_IPV6,
    environment.INTERNAL_GATEWAY_IPV6,
  ];
  const hostTrapPort = Number(environment.HOST_TRAP_PORT);
  if (
    ipv4Targets.some((address) => isIP(address) !== 4) ||
    ipv6Targets.some((address) => isIP(address) !== 6) ||
    !Number.isSafeInteger(hostTrapPort) ||
    hostTrapPort < 1 ||
    hostTrapPort > 65535
  )
    throw new Error("invalid_tcp_bypass_target");

  return [
    {
      label: "raw_tcp_supervisor_ipv4_bypass",
      host: environment.SUPERVISOR_EXTERNAL_IP,
      port: 8080,
    },
    {
      label: "raw_tcp_supervisor_ipv6_bypass",
      host: environment.SUPERVISOR_EXTERNAL_IPV6,
      port: 8080,
    },
    {
      label: "raw_tcp_origin_ipv4_bypass",
      host: environment.ORIGIN_EXTERNAL_IP,
      port: 8081,
    },
    {
      label: "raw_tcp_origin_ipv6_bypass",
      host: environment.ORIGIN_EXTERNAL_IPV6,
      port: 8081,
    },
    {
      label: "raw_tcp_host_service_bypass",
      host: "host.docker.internal",
      port: hostTrapPort,
    },
    {
      label: "raw_tcp_host_gateway_ipv4_bypass",
      host: environment.INTERNAL_GATEWAY_IP,
      port: hostTrapPort,
    },
    {
      label: "raw_tcp_host_gateway_ipv6_bypass",
      host: environment.INTERNAL_GATEWAY_IPV6,
      port: hostTrapPort,
    },
  ];
}

export function assertTcpUnreachable(label, host, port) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    let settled = false;
    const timer = setTimeout(() => {
      settled = true;
      socket.destroy();
      resolve();
    }, 1500);
    socket.once("connect", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(new Error(`${label}_reachable`));
    });
    socket.once("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    });
  });
}
